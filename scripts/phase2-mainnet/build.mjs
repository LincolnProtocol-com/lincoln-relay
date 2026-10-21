#!/usr/bin/env node
// Separate mainnet release-candidate compiler. Never reads wallet keys or broadcasts.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {readMainnetPlan} from './plan.mjs';
import {createBeaconEvidenceLoader} from '../phase2-ceremony/evidence.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const hash=value=>createHash('sha256').update(value).digest('hex');
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const TEST_GUARD='if (block.chainid != 31341 && block.chainid != 46630) revert UnsupportedChainId();';
const MAINNET_GUARD='if (block.chainid != 4663) revert UnsupportedChainId();';
const SOURCES=Object.freeze([
  ['protocol/phase2-asp/contracts/Phase2ASPPool.sol','protocol/phase2-mainnet/contracts/Phase2ASPPool.sol'],
  ['protocol/phase2-asp/contracts/Phase2ASPRegistry.sol','protocol/phase2-mainnet/contracts/Phase2ASPRegistry.sol'],
  ['protocol/phase2-routes/contracts/Phase2RouteAdapter.sol','protocol/phase2-mainnet/contracts/Phase2RouteAdapter.sol'],
  ['protocol/phase2-router02/contracts/Phase2Router02Adapter.sol','protocol/phase2-mainnet/contracts/Phase2Router02Adapter.sol'],
]);
const PARAMETER_ROOT='protocol/phase2-mainnet/';
const PTAU='vendor/nocturne-protocol/packages/circuits/data/powersOfTau28_hez_final_15.ptau';
const PTAU_SHA='3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f';
const SIGNALS={joinsplit:9,'holder-exit':5};
const VERIFIERS={joinsplit:'Phase2ASPJoinSplitVerifier','holder-exit':'Phase2ASPExitVerifier'};

export function deriveSource(original){
  need(original.split(TEST_GUARD).length===2,'MAINNET_SOURCE_GUARD_DRIFT');
  return original.replace(TEST_GUARD,MAINNET_GUARD)
    .replace('Only test-chain development verifiers and exact-transfer assets are supported.',
      'Mainnet release candidate with finalized verifier bindings; exact-transfer assets only.')
    .replace('These binaries use a self-generated development key. Keeping a chain',
      'This mainnet build binds separately finalized Groth16 verifiers. A chain')
    .replace('allowlist in the bytecode prevents accidental use on a production chain.',
      'allowlist in the bytecode restricts this candidate to Robinhood mainnet.')
    .replace('Development deployment.','Mainnet release candidate.');
}
async function regular(root,relative){
  need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(part=>part&&part!=='.'&&part!=='..'&&!part.startsWith('.')),'MAINNET_BUILD_PUBLIC_PATH_REQUIRED');
  const filename=path.resolve(root,relative);need(filename.startsWith(root+path.sep),'MAINNET_BUILD_PUBLIC_PATH_REQUIRED');
  let stat;try{stat=await fs.lstat(filename);}catch(error){if(error.code==='ENOENT')throw Object.assign(new Error('MAINNET_FINAL_PARAMETER_MISSING'),{code:'MAINNET_FINAL_PARAMETER_MISSING'});throw error;}
  need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(filename)===filename,'MAINNET_BUILD_REGULAR_FILE_REQUIRED');
  return fs.readFile(filename);
}
function artifactPath(reference){
  need(reference&&typeof reference.path==='string'&&reference.path.startsWith(PARAMETER_ROOT)&&/^[a-f0-9]{64}$/.test(reference.sha256),'MAINNET_PARAMETER_REFERENCE_INVALID');
  return reference.path;
}
export function canonicalProductionVerifier(source,name){
  need(Object.values(VERIFIERS).includes(name)&&source.includes('// SPDX-License-Identifier: GPL-3.0')
    &&source.includes('pragma solidity >=0.7.0 <0.9.0;')&&source.includes('contract Groth16Verifier {'),'MAINNET_VERIFIER_TEMPLATE_INVALID');
  return source.replace('pragma solidity >=0.7.0 <0.9.0;','pragma solidity 0.8.28;').replace('contract Groth16Verifier {',`contract ${name} {`);
}

/** No writes happen until both circuits have passed their full artifact checks. */
export async function loadFinalProductionCircuit({root=ROOT,name}={}){
  root=await fs.realpath(root);need(Object.hasOwn(SIGNALS,name),'MAINNET_CIRCUIT_NAME_INVALID');
  const manifestPath=`${PARAMETER_ROOT}build/${name}/manifest.json`;
  const bytes=await regular(root,manifestPath),manifest=JSON.parse(bytes.toString('utf8'));
  need(manifest.schema==='phase2-asp-production-circuits/v1'&&manifest.testOnly===false
    &&JSON.stringify(manifest.allowedChainIds)==='[4663]'&&manifest.setup?.kind==='multi-party-phase2'
    &&manifest.protocol==='groth16'&&manifest.curve==='bn128','MAINNET_DEVELOPMENT_PARAMETERS_REJECTED');
  need(manifest.inputs?.circuit===name&&manifest.counts?.publicInputs===SIGNALS[name]&&manifest.counts?.outputs===0
    &&(name!=='joinsplit'||manifest.inputs.maxTreeDepth===20&&manifest.inputs.policyMode==='asp'),'MAINNET_CIRCUIT_INTERFACE_INVALID');
  need(Array.isArray(manifest.inputs.sources)&&manifest.inputs.sources.length>0,'MAINNET_CIRCUIT_SOURCES_REQUIRED');
  for(const reference of manifest.inputs.sources){
    need(reference.path.startsWith('protocol/phase2-asp/circuits/')||reference.path.startsWith(PARAMETER_ROOT+'circuits/'),'MAINNET_CIRCUIT_SOURCE_PATH_INVALID');
    need(/^[a-f0-9]{64}$/.test(reference.sha256)&&hash(await regular(root,reference.path))===reference.sha256,'MAINNET_CIRCUIT_SOURCE_DIGEST_MISMATCH');
  }
  const files={};
  for(const key of ['r1cs','wasm','zkey','vkey','verifier']){
    const reference=manifest.artifacts?.[key],relative=artifactPath(reference),data=await regular(root,relative);
    need(hash(data)===reference.sha256&&(reference.bytes===undefined||reference.bytes===data.length),'MAINNET_PARAMETER_DIGEST_MISMATCH');
    files[key]={path:relative,absolute:path.join(root,relative),bytes:data};
  }
  need(files.verifier.path===`${PARAMETER_ROOT}generated/${VERIFIERS[name]}.sol`,'MAINNET_VERIFIER_PATH_INVALID');
  const baseline=JSON.parse((await regular(root,`artifacts/phase2-asp/circuits/${name}/manifest.json`)).toString('utf8'));
  need(hash(files.zkey.bytes)!==baseline.artifacts?.zkey?.sha256,'MAINNET_DEVELOPMENT_KEY_REUSE_REJECTED');
  // R1CS/WASM contain no toxic waste. Pin their tested circuit computation while
  // requiring a different final phase-2 zkey, rather than accepting any 9/5-input circuit.
  need(hash(files.r1cs.bytes)===baseline.artifacts?.r1cs?.sha256&&hash(files.wasm.bytes)===baseline.artifacts?.wasm?.sha256
    &&isDeepStrictEqual(manifest.inputs.sources,baseline.inputs.sources),'MAINNET_APPROVED_CIRCUIT_BINDING_MISMATCH');
  need(manifest.phase1?.path===PTAU&&manifest.phase1.sha256===PTAU_SHA,'MAINNET_PHASE1_PIN_REQUIRED');
  const ptau=await regular(root,PTAU);need(hash(ptau)===PTAU_SHA,'MAINNET_PHASE1_DIGEST_MISMATCH');
  const transcriptRef=manifest.artifacts?.ceremonyTranscript;
  const transcriptPath=artifactPath(transcriptRef),transcriptBytes=await regular(root,transcriptPath);
  need(hash(transcriptBytes)===transcriptRef.sha256,'MAINNET_CEREMONY_TRANSCRIPT_DIGEST_MISMATCH');
  files.ceremonyTranscript={path:transcriptPath,absolute:path.join(root,transcriptPath),bytes:transcriptBytes};
  return {name,manifest,manifestPath,manifestSHA256:hash(bytes),files,ptau};
}

export function validateEmbeddedMPC(contributions,transcript,{name,r1csSHA256,ptauSHA256,zkeySHA256}={}){
  need(Array.isArray(contributions)&&contributions.length>=3&&contributions.length<=10000,'MAINNET_MPC_CONTRIBUTIONS_REQUIRED');
  const participants=contributions.slice(0,-1),beacon=contributions.at(-1);
  need(participants.length>=2&&participants.every(c=>c.type===0&&typeof c.name==='string'&&c.name.length>0)
    &&new Set(participants.map(c=>c.name)).size===participants.length,'MAINNET_MPC_CONTRIBUTORS_REQUIRED');
  need(beacon.type===1&&/^0x[0-9a-f]{2,510}$/.test(beacon.beaconHash??'')&&beacon.beaconHash.length%2===0
    &&Number.isInteger(beacon.numIterationsExp)&&beacon.numIterationsExp>=10&&beacon.numIterationsExp<=63,'MAINNET_FINAL_BEACON_REQUIRED');
  need(transcript?.schema==='phase2-asp-ceremony-transcript/v1'&&transcript.circuit===name
    &&transcript.r1csSHA256===r1csSHA256&&transcript.ptauSHA256===ptauSHA256&&transcript.finalZkeySHA256===zkeySHA256,'MAINNET_CEREMONY_TRANSCRIPT_BINDING_MISMATCH');
  need(isDeepStrictEqual(transcript.contributions,contributions),'MAINNET_EMBEDDED_MPC_TRANSCRIPT_MISMATCH');
  return {embeddedContributionCount:contributions.length,nonBeaconContributors:participants.length,finalBeacon:true,
    transcriptBound:true,independentOperatorIdentityAuthenticated:false};
}

/** Read the real binary section 10, rather than trusting manifest setup labels. */
export async function readEmbeddedMPC({root=ROOT,zkeyPath,includeContributionHashes=false}={}){
  root=await fs.realpath(root);
  const {readBinFile}=await import('@iden3/binfileutils');
  const utilitiesPath=path.join(root,'node_modules/snarkjs/src/zkey_utils.js');
  await regular(root,'node_modules/snarkjs/src/zkey_utils.js');
  const {readHeader,readMPCParams,hashPubKey}=await import(pathToFileURL(utilitiesPath).href);
  let Blake2b;
  if(includeContributionHashes){({default:Blake2b}=await import('blake2b-wasm'));await Blake2b.ready();}
  let fd,curve;
  try{
    const binary=await readBinFile(zkeyPath,'zkey',2);fd=binary.fd;
    const header=await readHeader(fd,binary.sections,false,{singleThread:true});curve=header.curve;
    need(header.protocol==='groth16','MAINNET_MPC_PROTOCOL_INVALID');
    const mpc=await readMPCParams(fd,curve,binary.sections);
    return mpc.contributions.map(c=>{
      let contributionHashHex;
      if(includeContributionHashes){const h=Blake2b(64);hashPubKey(h,curve,c);contributionHashHex='0x'+Buffer.from(h.digest()).toString('hex');}
      return {type:c.type,name:c.name??'',transcriptHex:'0x'+Buffer.from(c.transcript).toString('hex'),
        ...(includeContributionHashes?{contributionHashHex}:{}),
        ...(c.type===1?{beaconHash:'0x'+Buffer.from(c.beaconHash).toString('hex'),numIterationsExp:c.numIterationsExp}:{})};
    });
  }finally{await fd?.close();await curve?.terminate();}
}

export async function verifyFinalProductionCircuit(circuit,{root=ROOT}={}){
  root=await fs.realpath(root);
  const pkg=JSON.parse((await regular(root,'node_modules/snarkjs/package.json')).toString('utf8'));
  need(pkg.version==='0.7.5','MAINNET_SNARKJS_VERSION_MISMATCH');
  const contributions=await readEmbeddedMPC({root,zkeyPath:circuit.files.zkey.absolute});
  const mpc=validateEmbeddedMPC(contributions,JSON.parse(circuit.files.ceremonyTranscript.bytes.toString('utf8')),
    {name:circuit.name,r1csSHA256:hash(circuit.files.r1cs.bytes),ptauSHA256:hash(circuit.ptau),zkeySHA256:hash(circuit.files.zkey.bytes)});
  const evidence=circuit.manifest.beaconEvidence;
  need(evidence?.schema==='phase2-production-beacon-binding/v1'&&evidence.independentOperatorIdentityAuthenticated===false
    &&evidence.publicPrecommitTimingCryptographicallyAuthenticated===false,'MAINNET_BEACON_EVIDENCE_REQUIRED');
  // Runtime releases carry approved computation and pinned dependencies. Recheck
  // both release circuits here; the offline finalizer also verifies the full
  // ceremony tool freeze, which is intentionally absent from the API image.
  const loadEvidence=createBeaconEvidenceLoader({
    inspect:(directory,zkeyPath)=>readEmbeddedMPC({root:directory,zkeyPath,includeContributionHashes:true}),
    verify:async directory=>{for(const name of Object.keys(SIGNALS))await loadFinalProductionCircuit({root:directory,name});},
  });
  const verified=await loadEvidence({rootDirectory:root,applicationPath:evidence.application?.path});
  const expectedEvidence={schema:'phase2-production-beacon-binding/v1',application:verified.application,commitment:verified.commitment,
    publication:verified.publication,observation:verified.observation,beaconHash:verified.beaconHash,iterations:verified.iterations,
    independentOperatorIdentityAuthenticated:false,publicPrecommitTimingCryptographicallyAuthenticated:false};
  need(isDeepStrictEqual(evidence,expectedEvidence)&&isDeepStrictEqual(JSON.parse(circuit.files.ceremonyTranscript.bytes).beaconEvidence,evidence)
    &&verified.circuits[circuit.name].finalZkey.sha256===hash(circuit.files.zkey.bytes),'MAINNET_BEACON_EVIDENCE_BINDING_MISMATCH');
  const {zKey}=await import('snarkjs'),quiet={debug(){},info(){},warn(){},error(){}};
  need(await zKey.verifyFromR1cs(circuit.files.r1cs.absolute,circuit.ptau,circuit.files.zkey.absolute,quiet)===true,'MAINNET_FINAL_KEY_R1CS_MISMATCH');
  const actual=await zKey.exportVerificationKey(circuit.files.zkey.absolute,quiet),declared=JSON.parse(circuit.files.vkey.bytes.toString('utf8'));
  need(actual.protocol==='groth16'&&actual.curve==='bn128'&&actual.nPublic===SIGNALS[circuit.name]&&isDeepStrictEqual(actual,declared),'MAINNET_FINAL_VKEY_MISMATCH');
  const template=(await regular(root,'node_modules/snarkjs/templates/verifier_groth16.sol.ejs')).toString('utf8');
  const exported=canonicalProductionVerifier(await zKey.exportSolidityVerifier(circuit.files.zkey.absolute,{groth16:template},quiet),VERIFIERS[circuit.name]);
  need(exported===circuit.files.verifier.bytes.toString('utf8'),'MAINNET_FINAL_VERIFIER_BINDING_MISMATCH');
  return {verifyFromR1cs:true,verificationKeyBound:true,solidityVerifierBound:true,...mpc};
}

/** Low-level compiler for validated sources. The CLI always validates final keys first. */
export async function compileMainnetSources({root=ROOT,sources}={}){
  root=await fs.realpath(root);const {default:solc}=await import('solc');
  need(solc.version().startsWith('0.8.28+'),'MAINNET_SOLC_VERSION_MISMATCH');
  const sourceDigests={};
  const dep=async relative=>{const data=await regular(root,relative);sourceDigests[relative]=hash(data);return data.toString('utf8');};
  for(const [name,version]of [['@openzeppelin/contracts','5.0.2'],['poseidon-solidity','0.0.5']])
    need(JSON.parse(await dep(`node_modules/${name}/package.json`)).version===version,'MAINNET_DEPENDENCY_VERSION_MISMATCH');
  // Load a finite import set before the synchronous compiler callback.
  const dependencies={};
  for(const name of ['@openzeppelin/contracts/utils/ReentrancyGuard.sol','@openzeppelin/contracts/token/ERC20/IERC20.sol',
    '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol','@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol',
    '@openzeppelin/contracts/utils/Address.sol','poseidon-solidity/PoseidonT3.sol','poseidon-solidity/PoseidonT4.sol'])
    dependencies[name]=await dep('node_modules/'+name);
  for(const [name,content]of Object.entries(sources))sourceDigests[name]=hash(content);
  const input={language:'Solidity',sources:Object.fromEntries(Object.entries(sources).map(([name,content])=>[name,{content}])),
    settings:{optimizer:{enabled:true,runs:10000},viaIR:true,evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode','evm.deployedBytecode']}}}};
  const output=JSON.parse(solc.compile(JSON.stringify(input),{import(name){return Object.hasOwn(dependencies,name)?{contents:dependencies[name]}:{error:'Import outside pinned mainnet compiler dependency set.'};}}));
  const libraryInput={language:'Solidity',sources:Object.fromEntries(['PoseidonT3','PoseidonT4'].map(name=>[`poseidon-solidity/${name}.sol`,{content:dependencies[`poseidon-solidity/${name}.sol`]}])),
    settings:{optimizer:{enabled:true,runs:10000},viaIR:false,evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode','evm.deployedBytecode']}}}};
  const libraries=JSON.parse(solc.compile(JSON.stringify(libraryInput))),diagnostics=[...(output.errors??[]),...(libraries.errors??[])];
  need(!diagnostics.some(item=>item.severity==='error'),'MAINNET_SOLIDITY_COMPILATION_FAILED');
  const selected=new Set(['Phase2ASPPool','Phase2ASPRegistry','Phase2RouteAdapter','Phase2Router02Adapter',...Object.values(VERIFIERS)]),contracts={};
  const add=(source,name,contract)=>{
    need(!contracts[name]&&contract?.evm?.bytecode?.object,'MAINNET_COMPILED_CONTRACT_MISSING');
    need(contract.evm.deployedBytecode.object.length/2<=24576&&contract.evm.bytecode.object.length/2<=49152,'MAINNET_CONTRACT_TOO_LARGE');
    contracts[name]={source,abi:contract.abi,bytecode:'0x'+contract.evm.bytecode.object,deployedBytecode:'0x'+contract.evm.deployedBytecode.object,
      linkReferences:contract.evm.bytecode.linkReferences,deployedLinkReferences:contract.evm.deployedBytecode.linkReferences,immutableReferences:contract.evm.deployedBytecode.immutableReferences};
  };
  for(const [source,items]of Object.entries(output.contracts??{}))for(const [name,item]of Object.entries(items))if(selected.has(name))add(source,name,item);
  for(const name of ['PoseidonT3','PoseidonT4'])add('poseidon-solidity/'+name+'.sol',name,libraries.contracts?.['poseidon-solidity/'+name+'.sol']?.[name]);
  need([...selected].every(name=>contracts[name]),'MAINNET_COMPILED_CONTRACT_MISSING');
  for(const [name,count]of Object.entries(VERIFIERS).map(([c,n])=>[n,SIGNALS[c]])){
    const proof=contracts[name].abi.find(item=>item.name==='verifyProof'&&item.type==='function');
    need(proof&&JSON.stringify(proof.inputs.map(item=>item.type))===JSON.stringify(['uint256[2]','uint256[2][2]','uint256[2]',`uint256[${count}]`]),'MAINNET_VERIFIER_ABI_MISMATCH');
  }
  for(const name of ['Phase2ASPPool','Phase2RouteAdapter','Phase2Router02Adapter'])
    need(!contracts[name].abi.some(item=>item.type==='function'&&/^(owner|admin|upgrade|set|pause|grant|revoke|sweep)/i.test(item.name)
      &&!(name==='Phase2ASPPool'&&['setCaps','pauseDeposits'].includes(item.name))),'MAINNET_PRIVILEGED_FUNCTION_REJECTED');
  return {contracts,compiler:solc.version(),sourceDigests,sourceSetSHA256:hash(JSON.stringify(Object.entries(sourceDigests).sort())),
    inputSHA256:hash(JSON.stringify({input,libraryInput})),diagnostics:diagnostics.map(({severity,formattedMessage})=>({severity,formattedMessage}))};
}

async function writeExact(root,relative,bytes){
  const filename=path.join(root,relative);await fs.mkdir(path.dirname(filename),{recursive:true});
  need(await fs.realpath(path.dirname(filename))===path.dirname(filename),'MAINNET_OUTPUT_DIRECTORY_INVALID');
  try{const old=await regular(root,relative);need(old.equals(Buffer.from(bytes)),'MAINNET_OUTPUT_ALREADY_DIFFERS');return;}
  catch(error){if(error.code!=='MAINNET_FINAL_PARAMETER_MISSING')throw error;}
  await fs.writeFile(filename,bytes,{flag:'wx',mode:0o644});
}
export async function buildMainnetRelease({root=ROOT}={}){
  root=await fs.realpath(root);const plan=await readMainnetPlan({root});
  need(plan.policyMode==='asp'&&plan.selected==='aspSelfHosted'&&plan.deploymentBuildEnabled,'MAINNET_BUILD_POLICY_UNSUPPORTED');
  let lock;
  try{
    const circuits={};for(const name of Object.keys(SIGNALS))circuits[name]=await loadFinalProductionCircuit({root,name});
    for(const circuit of Object.values(circuits))circuit.verified=await verifyFinalProductionCircuit(circuit,{root});
    const sources={},sourceDerivation=[];for(const [source,target]of SOURCES){
      const original=(await regular(root,source)).toString('utf8');sources[target]=deriveSource(original);
      sourceDerivation.push({source,target,sourceSHA256:hash(original),derivedSourceSHA256:hash(sources[target])});
    }
    for(const circuit of Object.values(circuits))sources[circuit.files.verifier.path]=circuit.files.verifier.bytes.toString('utf8');
    const compiled=await compileMainnetSources({root,sources});
    // Recheck all final inputs after expensive crypto/compilation, before publishing.
    for(const circuit of Object.values(circuits)){
      need(hash(await regular(root,circuit.manifestPath))===circuit.manifestSHA256,'MAINNET_INPUT_CHANGED_DURING_BUILD');
      for(const file of Object.values(circuit.files))need(hash(await regular(root,file.path))===hash(file.bytes),'MAINNET_INPUT_CHANGED_DURING_BUILD');
    }
    const result={_meta:{schema:'phase2-asp-production-build/v1',releaseCandidate:true,testOnly:false,productionReady:false,
      allowedChainIds:[4663],policyMode:'asp',compiler:compiled.compiler,optimizerRuns:10000,viaIR:true,evmVersion:'cancun',
      inputSHA256:compiled.inputSHA256,sourceDigests:compiled.sourceDigests,sourceSetSHA256:compiled.sourceSetSHA256,sourceDerivation,
      circuits:Object.fromEntries(Object.entries(circuits).map(([name,c])=>[name,{manifest:c.manifestPath,manifestSHA256:c.manifestSHA256,zkeySHA256:hash(c.files.zkey.bytes),...c.verified}])),
      audit:plan.audit,diagnostics:compiled.diagnostics,
      limitations:['Compilation binds finalized proof artifacts; it is not an independent audit or deployment authorization.',
        'Operator identity and independence are not authenticated by the compiler. Existing development keys are explicitly rejected.',
        'No transactions are signed or broadcast by this build command.']},...compiled.contracts};
    const outDir=path.join(root,'artifacts/phase2-mainnet');await fs.mkdir(outDir,{recursive:true});
    need(await fs.realpath(outDir)===outDir,'MAINNET_OUTPUT_DIRECTORY_INVALID');
    lock=await fs.open(path.join(outDir,'.build.lock'),'wx',0o600);
    for(const [filename,content]of Object.entries(sources))if(!filename.includes('/generated/'))await writeExact(root,filename,content);
    const serialized=JSON.stringify(result,null,2)+'\n';await writeExact(root,'artifacts/phase2-mainnet/contracts.json',serialized);
    return {schema:'lincoln-mainnet-build-result/v1',compiled:true,contracts:Object.keys(compiled.contracts).length,chainId:4663,
      artifact:'artifacts/phase2-mainnet/contracts.json',artifactSHA256:hash(serialized),productionReady:false,audit:plan.audit,transactionsBroadcast:0};
  }finally{
    if(lock){await lock.close();await fs.unlink(path.join(root,'artifacts/phase2-mainnet/.build.lock'));}
    if(globalThis.curve_bn128){await globalThis.curve_bn128.terminate();globalThis.curve_bn128=undefined;}
  }
}

export async function buildMainnetSourcePlan({root=ROOT}={}){
  root=await fs.realpath(root);const plan=await readMainnetPlan({root}),sources=[];
  for(const [source,target]of SOURCES){
    const filename=path.resolve(root,source),stat=await fs.lstat(filename);
    if(!stat.isFile()||stat.isSymbolicLink()||await fs.realpath(filename)!==filename)throw Object.assign(new Error('MAINNET_SOURCE_FILE_INVALID'),{code:'MAINNET_SOURCE_FILE_INVALID'});
    const original=await fs.readFile(filename,'utf8');
    if(original.split(TEST_GUARD).length!==2)throw Object.assign(new Error('MAINNET_SOURCE_GUARD_DRIFT'),{code:'MAINNET_SOURCE_GUARD_DRIFT'});
    const transformed=deriveSource(original);
    sources.push({source,target,sourceSHA256:hash(original),derivedGuardSourceSHA256:hash(transformed),oldGuard:TEST_GUARD,newGuard:MAINNET_GUARD});
  }
  return {schema:'lincoln-mainnet-source-build-plan/v1',chainId:4663,policyMode:plan.policyMode,selected:plan.selected,
    deploymentBuildEnabled:plan.deploymentBuildEnabled,sources,
    finalVerifierBindings:{joinsplit:{manifest:plan.circuits.joinsplit.path,generatedSource:'protocol/phase2-mainnet/generated/Phase2ASPJoinSplitVerifier.sol'},
      holderExit:{manifest:plan.circuits['holder-exit'].path,generatedSource:'protocol/phase2-mainnet/generated/Phase2ASPExitVerifier.sol'}},
    outputArtifact:plan.build.path,parameterMetadata:plan.circuits,
    compileImplemented:true,compiled:false,productionReady:false,readOnly:true,offline:true,filesWritten:0,transactionsBroadcast:0,
    pending:plan.pending,
    limitations:['The exact source chain guards and development-only comments are derived in memory and hashed; these hashes do not represent a compiled production artifact.',
      'Final production verifier sources must be derived from the actual finalized zkeys and bound to their manifests before compilation.',
      'Existing development source, verifiers, parameters and on-chain pools remain unchanged.']};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    need(process.argv.length===2||process.argv.length===3&&process.argv[2]==='--plan','USAGE_MAINNET_BUILD_PLAN');
    console.log(JSON.stringify(process.argv[2]==='--plan'?await buildMainnetSourcePlan():await buildMainnetRelease(),null,2));
  }catch(error){console.error(JSON.stringify({transactionsBroadcast:0,error:error.code??'MAINNET_BUILD_FAILED'}));process.exitCode=1;}
}
