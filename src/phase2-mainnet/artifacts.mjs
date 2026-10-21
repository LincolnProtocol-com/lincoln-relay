// SPDX-License-Identifier: Apache-2.0
// Final proving parameters are validated separately from the development SDK.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {loadFinalProductionCircuit} from '../../scripts/phase2-mainnet/build.mjs';
import {normalizeProfile,PRODUCTION_PROFILE_SCHEMA} from '../phase2-asp/sdk.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const verified=new Map(),inflight=new Map();

/** Each factory owns a different private brand. A caller-created loader cannot
 * mint a scope accepted by the production loader below. Scopes never survive
 * their callback and never persist a verification flag or file digest cache.
 */
export function createEphemeralValidationLoader({identity,load,copy=structuredClone}){
  need(typeof identity==='function'&&typeof load==='function'&&typeof copy==='function','MAINNET_VALIDATION_LOADER_INVALID');
  const scopes=new WeakMap();
  return Object.freeze({
    async withScope(callback){
      need(typeof callback==='function','MAINNET_VALIDATION_SCOPE_INVALID');
      const scope=Object.freeze(Object.create(null)),state={entries:new Map(),open:true};scopes.set(scope,state);
      try{return await callback(scope);}finally{state.open=false;state.entries.clear();scopes.delete(scope);}
    },
    async load(options){
      if(options.validationScope===undefined)return load(options);
      const state=scopes.get(options.validationScope);need(state?.open,'MAINNET_VALIDATION_SCOPE_CLOSED_OR_FOREIGN');
      // Identity validates every profile even when another pool already loaded
      // this exact root/build/manifests/optional parameter inventory.
      const key=await identity(options);need(state.open,'MAINNET_VALIDATION_SCOPE_CLOSED_OR_FOREIGN');
      if(!state.entries.has(key))state.entries.set(key,Promise.resolve().then(()=>load({...options,validationScope:undefined})));
      const result=await state.entries.get(key);need(state.open,'MAINNET_VALIDATION_SCOPE_CLOSED_OR_FOREIGN');return copy(result,options);
    },
  });
}

function canonical(value){
  if(Array.isArray(value)){need(Object.keys(value).length===value.length&&Object.keys(value).every((key,index)=>key===String(index)),'MAINNET_PRODUCTION_PIN_VALUE_INVALID');return value.map(canonical);}
  if(value&&typeof value==='object'){
    need(Object.getPrototypeOf(value)===Object.prototype,'MAINNET_PRODUCTION_PIN_VALUE_INVALID');
    return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  }
  need(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number'&&Number.isFinite(value),'MAINNET_PRODUCTION_PIN_VALUE_INVALID');
  return value;
}

export async function productionValidationIdentity({rootDirectory=ROOT,profile}){
  profile=structuredClone(profile);normalizeProfile(profile);need(profile.schema===PRODUCTION_PROFILE_SCHEMA,'MAINNET_PRODUCTION_PROFILE_REQUIRED');
  const root=await fs.realpath(rootDirectory);need(path.resolve(rootDirectory)===root,'MAINNET_CANONICAL_ROOT_REQUIRED');
  return sha(JSON.stringify(canonical({root,artifactSHA256:profile.artifactSHA256,production:profile.production})));
}

export async function readPublicProductionFile(root,relative,{maxBytes=128*1024*1024}={}){
  need(path.isAbsolute(root)&&await fs.realpath(root)===root,'MAINNET_CANONICAL_ROOT_REQUIRED');
  need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!p.startsWith('.')),'MAINNET_PUBLIC_PATH_REQUIRED');
  const filename=path.join(root,relative),handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await handle.stat();need(stat.isFile()&&stat.size<=maxBytes&&await fs.realpath(filename)===filename,'MAINNET_REGULAR_PUBLIC_FILE_REQUIRED');return await handle.readFile();}finally{await handle.close();}
}

/** Cache every byte needed to verify the beacon, including the two parent keys. */
export async function readPinnedBeaconFiles(root,beacon){
  need(beacon?.schema==='phase2-production-beacon-binding/v1','MAINNET_BEACON_EVIDENCE_REQUIRED');
  const files=new Map();let commitment;
  async function read(ref,maxBytes){
    need(ref&&/^[a-f0-9]{64}$/.test(ref.sha256)&&Number.isSafeInteger(ref.bytes)&&ref.bytes>0,'MAINNET_BEACON_REFERENCE_INVALID');
    const bytes=await readPublicProductionFile(root,ref.path,{maxBytes});
    need(bytes.length===ref.bytes&&sha(bytes)===ref.sha256,'MAINNET_BEACON_EVIDENCE_DIGEST_MISMATCH');
    files.set(ref.path,ref.sha256);return bytes;
  }
  for(const kind of ['application','commitment','publication','observation']){
    need(beacon[kind]?.path?.startsWith('artifacts/phase2-ceremony/'),'MAINNET_BEACON_REFERENCE_INVALID');
    const bytes=await read(beacon[kind],2*1024*1024);if(kind==='commitment')commitment=JSON.parse(bytes);
  }
  for(const name of ['joinsplit','holder-exit']){
    const ref=commitment?.body?.circuits?.[name]?.zkey;
    need(typeof ref?.path==='string'&&((ref.path.startsWith(`protocol/phase2-mainnet/build/${name}/`)
      &&ref.path.endsWith('.zkey')&&!ref.path.endsWith('/final.zkey'))
      ||new RegExp(`^artifacts/phase2-ceremony/contributions/[a-z][a-z0-9-]{2,63}/${name}\\.zkey$`).test(ref.path)),
    'MAINNET_BEACON_PARENT_REFERENCE_INVALID');
    await read(ref,128*1024*1024);
  }
  return files;
}

async function verifyInWorker(root){
  // The worker owns snarkjs curve threads; no wallet data or witness is sent.
  const moduleURL=new URL('./release.mjs',import.meta.url).href;
  const code=`let input='';for await(const c of process.stdin)input+=c;
try{const {root,moduleURL}=JSON.parse(input);const m=await import(moduleURL);
const result=await m.loadVerifiedMainnetRelease({root});
process.stdout.write(JSON.stringify({artifactSHA256:result.artifactSHA256,recompiledBytecode:true,finalParametersVerified:true}));process.exit(0);
}catch(e){process.stderr.write(/^[A-Z][A-Z0-9_]{1,80}$/.test(e.code??e.message)?e.code??e.message:'MAINNET_FINAL_VERIFICATION_FAILED');process.exit(1);}`;
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--input-type=module','-e',code],{cwd:root,stdio:['pipe','pipe','pipe']});
    let out='',err='',done=false;
    const finish=(error,result)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(result);};
    // Recompilation and both final-key transcript checks share small production
    // hosts with the indexer. Keep a bounded startup deadline without weakening
    // any of the cryptographic checks or persisting verification across boots.
    const timer=setTimeout(()=>{child.kill('SIGKILL');finish(Object.assign(new Error('MAINNET_FINAL_VERIFICATION_TIMEOUT'),{code:'MAINNET_FINAL_VERIFICATION_TIMEOUT'}));},900000);
    child.stdout.on('data',c=>{out+=c;if(out.length>65536){child.kill('SIGKILL');finish(new Error('MAINNET_VERIFICATION_OUTPUT_TOO_LARGE'));}});
    child.stderr.on('data',c=>{if(err.length<1024)err+=c;});
    child.on('error',()=>finish(new Error('MAINNET_VERIFICATION_WORKER_FAILED')));
    child.on('close',status=>{if(status!==0)return finish(Object.assign(new Error(/^[A-Z][A-Z0-9_]{1,80}$/.test(err)?err:'MAINNET_FINAL_VERIFICATION_FAILED'),{code:/^[A-Z][A-Z0-9_]{1,80}$/.test(err)?err:'MAINNET_FINAL_VERIFICATION_FAILED'}));try{finish(null,JSON.parse(out));}catch{finish(new Error('MAINNET_VERIFICATION_RESULT_INVALID'));}});
    child.stdin.on('error',()=>{});child.stdin.end(JSON.stringify({root,moduleURL}));
  });
}

/** Full cryptographic binding once per content digest; every call rereads all pins. */
async function loadProductionReleaseUnscoped({rootDirectory=ROOT,profile}={}){
  profile=structuredClone(profile);
  normalizeProfile(profile);need(profile.schema===PRODUCTION_PROFILE_SCHEMA,'MAINNET_PRODUCTION_PROFILE_REQUIRED');
  const root=await fs.realpath(rootDirectory);need(path.resolve(rootDirectory)===root,'MAINNET_CANONICAL_ROOT_REQUIRED');
  const buildBytes=await readPublicProductionFile(root,profile.production.build.path),artifactSHA256=sha(buildBytes);
  need(artifactSHA256===profile.artifactSHA256&&artifactSHA256===profile.production.build.sha256,'MAINNET_ARTIFACT_PROFILE_MISMATCH');
  const artifacts=JSON.parse(buildBytes.toString('utf8')),meta=artifacts._meta;
  need(meta?.schema==='phase2-asp-production-build/v1'&&meta.releaseCandidate===true&&meta.testOnly===false&&meta.productionReady===false&&JSON.stringify(meta.allowedChainIds)==='[4663]'&&meta.policyMode==='asp','MAINNET_PRODUCTION_BUILD_REQUIRED');
  for(const name of ['Phase2ASPPool','Phase2ASPRegistry','Phase2ASPJoinSplitVerifier','Phase2ASPExitVerifier','Phase2RouteAdapter','Phase2Router02Adapter'])need(Array.isArray(artifacts[name]?.abi)&&typeof artifacts[name].bytecode==='string'&&artifacts[name].bytecode.startsWith('0x'),'MAINNET_CONTRACT_ARTIFACT_REQUIRED');
  const circuits={},descriptors={},beaconFiles=new Map();
  for(const name of ['joinsplit','holder-exit']){
    const circuit=await loadFinalProductionCircuit({root,name}),pin=profile.production.manifests[name],binding=meta.circuits?.[name];
    need(circuit.manifestPath===pin.path&&circuit.manifestSHA256===pin.sha256&&binding?.manifest===pin.path&&binding.manifestSHA256===pin.sha256,'MAINNET_FINAL_MANIFEST_PROFILE_MISMATCH');
    need(binding.zkeySHA256===sha(circuit.files.zkey.bytes)&&binding.verifyFromR1cs===true&&binding.verificationKeyBound===true&&binding.solidityVerifierBound===true&&binding.finalBeacon===true&&binding.transcriptBound===true&&binding.nonBeaconContributors>=2,'MAINNET_FINAL_BUILD_BINDING_REQUIRED');
    if(profile.production.parameters!==undefined){const parameters=profile.production.parameters[name];need(parameters&&Object.keys(parameters).sort().join(',')===Object.keys(circuit.files).sort().join(','),'MAINNET_PARAMETER_PROFILE_INVENTORY_MISMATCH');for(const [key,file]of Object.entries(circuit.files))need(parameters[key]?.path===file.path&&parameters[key].sha256===sha(file.bytes),'MAINNET_PARAMETER_PROFILE_PIN_MISMATCH');}
    const beaconDigests=Object.fromEntries(await readPinnedBeaconFiles(root,circuit.manifest.beaconEvidence));
    for(const [relative,digest]of Object.entries(beaconDigests))beaconFiles.set(relative,digest);
    descriptors[name]={manifest:circuit.manifestSHA256,files:Object.fromEntries(Object.entries(circuit.files).map(([key,file])=>[key,sha(file.bytes)])),ptau:sha(circuit.ptau),beacon:beaconDigests};
    circuits[name]=circuit;
  }
  // Source/dependency edits invalidate the compile cache too, even if an old
  // contracts.json and proving key still have their expected byte hashes.
  const sources={};for(const [relative,expected]of Object.entries(meta.sourceDigests??{})){const actual=sha(await readPublicProductionFile(root,relative));need(actual===expected,'MAINNET_SOURCE_DIGEST_MISMATCH');sources[relative]=actual;}
  need(Object.keys(sources).length>4,'MAINNET_SOURCE_INVENTORY_REQUIRED');
  need(Array.isArray(meta.sourceDerivation)&&meta.sourceDerivation.length===4,'MAINNET_SOURCE_DERIVATION_REQUIRED');
  for(const entry of meta.sourceDerivation){const actual=sha(await readPublicProductionFile(root,entry.source));need(actual===entry.sourceSHA256,'MAINNET_SOURCE_DERIVATION_MISMATCH');sources[entry.source]=actual;}
  const cacheKey=sha(JSON.stringify({root,artifactSHA256,descriptors,sources}));
  if(!verified.has(cacheKey)){
    if(!inflight.has(cacheKey))inflight.set(cacheKey,verifyInWorker(root).then(result=>{need(result.artifactSHA256===artifactSHA256,'MAINNET_VERIFIED_BUILD_CHANGED');verified.set(cacheKey,result);if(verified.size>8)verified.delete(verified.keys().next().value);return result;}).finally(()=>inflight.delete(cacheKey)));
    await inflight.get(cacheKey);
  }
  for(const circuit of Object.values(circuits)){
    // Detect replacement while the expensive worker verified the same filenames.
    need(sha(await readPublicProductionFile(root,circuit.manifestPath))===circuit.manifestSHA256,'MAINNET_PARAMETERS_CHANGED_DURING_VERIFICATION');
    for(const file of Object.values(circuit.files))need(sha(await readPublicProductionFile(root,file.path))===sha(file.bytes),'MAINNET_PARAMETERS_CHANGED_DURING_VERIFICATION');
    circuit.verified=structuredClone(verified.get(cacheKey));
  }
  for(const [relative,expected]of Object.entries(sources))need(sha(await readPublicProductionFile(root,relative))===expected,'MAINNET_SOURCES_CHANGED_DURING_VERIFICATION');
  for(const [relative,expected]of beaconFiles)need(sha(await readPublicProductionFile(root,relative))===expected,'MAINNET_BEACON_EVIDENCE_CHANGED_DURING_VERIFICATION');
  need(sha(await readPublicProductionFile(root,profile.production.build.path))===artifactSHA256,'MAINNET_BUILD_CHANGED_DURING_VERIFICATION');
  return {schema:'phase2-asp-validated-production-release/v1',artifactSHA256,artifacts,circuits,rootDirectory:root,releaseCandidate:true,testOnly:false,productionReady:false};
}

// Runtime startup needs ABI/bytecode and release bindings, never the large proof
// buffers. Keep those only in this private scope and deep-copy the JSON view.
const runtimeReleaseView=release=>structuredClone({schema:'phase2-asp-validated-production-runtime-release/v1',artifactSHA256:release.artifactSHA256,
  artifacts:release.artifacts,rootDirectory:release.rootDirectory,releaseCandidate:release.releaseCandidate,testOnly:release.testOnly,productionReady:release.productionReady});
export function cloneProductionRelease(value){
  if(Buffer.isBuffer(value))return Buffer.from(value);
  if(Array.isArray(value))return value.map(cloneProductionRelease);
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,cloneProductionRelease(item)]));
  return value;
}
const productionValidation=createEphemeralValidationLoader({identity:productionValidationIdentity,load:loadProductionReleaseUnscoped,
  copy:(release,options)=>options.runtimeOnly?runtimeReleaseView(release):cloneProductionRelease(release)});
export const withProductionReleaseValidation=callback=>productionValidation.withScope(callback);
export function loadProductionRuntimeRelease(options={}){
  need(options.validationScope!==undefined,'MAINNET_RUNTIME_VALIDATION_SCOPE_REQUIRED');
  return productionValidation.load({...options,profile:structuredClone(options.profile),runtimeOnly:true});
}
// Preserve the SDK/full-loader byte-buffer interface and its per-call complete
// pin reads. Explicit scoped full reads also retain Buffer semantics and cannot
// mutate the private memo; the API startup path uses the smaller JSON view.
export const loadProductionRelease=(options={})=>productionValidation.load({...options,profile:structuredClone(options.profile),runtimeOnly:false});
