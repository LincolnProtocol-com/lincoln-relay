#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Finite public production inputs only. No wallets, runtime journals or ceremony entropy.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function publicPath(relative){
  need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!p.startsWith('.')),'MAINNET_STAGE_PUBLIC_PATH_REQUIRED');
  need((relative==='config/phase2-mainnet.json'||relative==='artifacts/phase2-mainnet/contracts.json'
    ||relative==='artifacts/phase2-fees-mainnet/contracts.json'||/^artifacts\/phase2-asp\/circuits\/(joinsplit|holder-exit)\/manifest\.json$/.test(relative)
    ||relative.startsWith('artifacts/phase2-ceremony/')||relative.startsWith('protocol/')||relative.startsWith('node_modules/')
    ||relative==='vendor/nocturne-protocol/packages/circuits/data/powersOfTau28_hez_final_15.ptau')
    &&!/(?:^|\/)(?:wallets?|secrets?|keystores?|runtime)(?:\/|$)|(?:\.password|\.token|\.log)$|witness/i.test(relative),'MAINNET_STAGE_PUBLIC_SCOPE_REQUIRED');
  return relative;
}

/** This verifies pin bytes, not the Groth16 equations. The runtime still verifies everything. */
export async function collectMainnetReleaseInputs({rootDirectory=ROOT,includeFeeComponent=false}={}){
  const root=await fs.realpath(rootDirectory),files=new Map(),dependencies=new Map();
  async function add(relative,expected={}){
    publicPath(relative);const filename=path.join(root,relative),h=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
    let bytes;
    try{const stat=await h.stat();need(stat.isFile()&&stat.size>0&&stat.size<=128*1024*1024&&await fs.realpath(filename)===filename,'MAINNET_STAGE_REGULAR_INPUT_REQUIRED');bytes=await h.readFile();}finally{await h.close();}
    const digest=sha(bytes);need(expected.sha256===undefined||expected.sha256===digest,'MAINNET_STAGE_INPUT_DIGEST_MISMATCH');need(expected.bytes===undefined||expected.bytes===bytes.length,'MAINNET_STAGE_INPUT_SIZE_MISMATCH');
    if(relative.startsWith('node_modules/'))dependencies.set(relative,{file:relative,sha256:digest,bytes:bytes.length});
    else{const prior=files.get(relative);need(!prior||prior.sha256===digest,'MAINNET_STAGE_INPUT_CHANGED');files.set(relative,{file:relative,sha256:digest,bytes:bytes.length,content:bytes});}
    return bytes;
  }
  const config=JSON.parse(await add('config/phase2-mainnet.json'));
  need(config.enabled===true&&config.chain?.id===4663&&config.network==='mainnet'&&config.productionArtifacts?.build==='artifacts/phase2-mainnet/contracts.json','MAINNET_STAGE_TARGET_INVALID');
  const core=JSON.parse(await add(config.productionArtifacts.build));
  need(core._meta?.schema==='phase2-asp-production-build/v1'&&core._meta.testOnly===false&&JSON.stringify(core._meta.allowedChainIds)==='[4663]','MAINNET_STAGE_PRODUCTION_BUILD_REQUIRED');
  for(const name of ['joinsplit','holder-exit']){
    const file=`protocol/phase2-mainnet/build/${name}/manifest.json`,pin=core._meta.circuits?.[name];
    need(pin?.manifest===file&&/^[a-f0-9]{64}$/.test(pin.manifestSHA256??''),'MAINNET_STAGE_FINAL_CIRCUIT_REQUIRED');
    const manifest=JSON.parse(await add(file,{sha256:pin.manifestSHA256}));
    need(manifest.schema==='phase2-asp-production-circuits/v1'&&manifest.testOnly===false,'MAINNET_STAGE_FINAL_CIRCUIT_REQUIRED');
    await add(`artifacts/phase2-asp/circuits/${name}/manifest.json`);
    for(const ref of [...Object.values(manifest.artifacts),...manifest.inputs.sources,manifest.phase1])await add(ref.path,ref);
    const evidence=manifest.beaconEvidence;
    need(evidence?.schema==='phase2-production-beacon-binding/v1','MAINNET_STAGE_BEACON_REQUIRED');
    let commitment;
    for(const kind of ['application','commitment','publication','observation']){
      const ref=evidence[kind];need(ref&&ref.path.startsWith('artifacts/phase2-ceremony/'),'MAINNET_STAGE_BEACON_REQUIRED');
      const bytes=await add(ref.path,ref);if(kind==='commitment')commitment=JSON.parse(bytes);
    }
    for(const circuit of ['joinsplit','holder-exit']){
      const ref=commitment?.body?.circuits?.[circuit]?.zkey;
      need(typeof ref?.path==='string'&&(new RegExp(`^artifacts/phase2-ceremony/contributions/[a-z][a-z0-9-]{2,63}/${circuit}\\.zkey$`).test(ref.path)
        ||ref.path.startsWith(`protocol/phase2-mainnet/build/${circuit}/`)&&ref.path.endsWith('.zkey')&&!ref.path.endsWith('/final.zkey')),'MAINNET_STAGE_BEACON_PARENT_REQUIRED');
      await add(ref.path,ref);
    }
  }
  for(const [file,digest]of Object.entries(core._meta.sourceDigests??{}))await add(file,{sha256:digest});
  need(Array.isArray(core._meta.sourceDerivation)&&core._meta.sourceDerivation.length===4,'MAINNET_STAGE_SOURCE_DERIVATION_REQUIRED');
  for(const ref of core._meta.sourceDerivation)await add(ref.source,{sha256:ref.sourceSHA256});
  if(includeFeeComponent){
    const component=JSON.parse(await add('artifacts/phase2-fees-mainnet/contracts.json'));
    need(component._meta?.schema==='phase2-fees-production-build/v1'&&component._meta.testOnly===false
      &&component._meta.coreRelease?.build?.sha256===sha(files.get(config.productionArtifacts.build).content),'MAINNET_STAGE_FEE_CORE_BINDING_MISMATCH');
    for(const [file,digest]of Object.entries(component._meta.sourceDigests??{}))await add(file,{sha256:digest});
  }
  return {files:[...files.values()].sort((a,b)=>a.file.localeCompare(b.file)),imageDependencies:[...dependencies.values()].sort((a,b)=>a.file.localeCompare(b.file))};
}

export async function stageMainnetPublicRelease({rootDirectory=ROOT,destination,includeFeeComponent=false}={}){
  need(typeof destination==='string'&&path.isAbsolute(destination)&&path.normalize(destination)===destination,'MAINNET_STAGE_ABSOLUTE_DESTINATION_REQUIRED');
  const parent=path.dirname(destination);need(await fs.realpath(parent)===parent,'MAINNET_STAGE_CANONICAL_DESTINATION_REQUIRED');
  // Finish input validation before creating an output. Never replace an old release.
  const inputs=await collectMainnetReleaseInputs({rootDirectory,includeFeeComponent});
  await fs.mkdir(destination,{mode:0o755});
  for(const file of inputs.files){const target=path.join(destination,file.file);await fs.mkdir(path.dirname(target),{recursive:true,mode:0o755});await fs.writeFile(target,file.content,{flag:'wx',mode:0o644});}
  const records=inputs.files.map(({content,...record})=>record),report={schema:'lincoln-mainnet-public-inputs/v1',chainId:4663,files:records,imageDependencies:inputs.imageDependencies,
    inputSetSHA256:sha(JSON.stringify({files:records,imageDependencies:inputs.imageDependencies})),totalBytes:records.reduce((s,f)=>s+f.bytes,0),secretsIncluded:false,
    provingParametersIncluded:true,cryptographicVerificationRequiredAtStartup:true,mainnetTransactionsAuthorized:false,transactionsBroadcast:0};
  await fs.writeFile(path.join(destination,'mainnet-public-inputs.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o644});
  return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  // --from <dir>: read the release from another checkout, e.g. Lincoln-protocol-core/releases/rc3.
  const args=process.argv.slice(2),usage='USAGE: node docker/mainnet/stage-public-release.mjs /absolute/NEW/public-release [--from /absolute/release-root] [--include-fees]';
  let destination,rootDirectory=ROOT,includeFeeComponent=false;
  for(let i=0;i<args.length;i++){
    if(args[i]==='--include-fees')includeFeeComponent=true;
    else if(args[i]==='--from'){rootDirectory=args[++i];if(typeof rootDirectory!=='string'||!path.isAbsolute(rootDirectory))throw new Error(usage);}
    else if(destination===undefined)destination=args[i];else throw new Error(usage);
  }
  stageMainnetPublicRelease({rootDirectory,destination,includeFeeComponent}).then(r=>console.log(JSON.stringify({inputSetSHA256:r.inputSetSHA256,files:r.files.length,totalBytes:r.totalBytes,transactionsBroadcast:0}))).catch(e=>{console.error(e.code??e.message);process.exit(1);});
}
