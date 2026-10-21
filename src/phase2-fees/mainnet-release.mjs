// SPDX-License-Identifier: Apache-2.0
// A distinct mainnet component, bound to a verified final pool release. No signer.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import solc from 'solc';

export const MAINNET_FEE_SOURCE='protocol/phase2-fees/mainnet/Phase2FeeRouteAdapter.sol';
export const AUDITED_FEE_SOURCE='protocol/phase2-fees/contracts/Phase2FeeRouteAdapter.sol';
export const MAINNET_FEE_ARTIFACT='artifacts/phase2-fees-mainnet/contracts.json';
export const MAINNET_FEE_INPUT='contracts/phase2-fees-mainnet.standard-input.json';
export const MAINNET_FEE_MANIFEST='contracts/phase2-fees-mainnet.manifest.json';
export const MAINNET_FEE_TYPES=Object.freeze(['Phase2FeeRouteAdapter','Phase2FeeRouter02Adapter']);
const CORE='artifacts/phase2-mainnet/contracts.json';
const IMPORTS=['protocol/phase2-mainnet/contracts/Phase2RouteAdapter.sol','protocol/phase2-mainnet/contracts/Phase2Router02Adapter.sol'];
export const feeSHA256=x=>createHash('sha256').update(x).digest('hex');
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const json=x=>JSON.stringify(x,null,2)+'\n';
const cache=new Map();

export function deriveMainnetFeeSource(original){
  const guard='if (block.chainid != 31341 && block.chainid != 46630 && block.chainid != 4663) revert UnsupportedChainId();';
  check(typeof original==='string'&&original.split(guard).length===2,'MAINNET_FEE_SOURCE_GUARD_DRIFT');
  let derived=original.replace(guard,'if (block.chainid != 4663) revert UnsupportedChainId();');
  for(const [before,after]of [
    ['../../phase2-routes/contracts/Phase2RouteAdapter.sol','../../phase2-mainnet/contracts/Phase2RouteAdapter.sol'],
    ['../../phase2-router02/contracts/Phase2Router02Adapter.sol','../../phase2-mainnet/contracts/Phase2Router02Adapter.sol'],
  ]){check(derived.split(before).length===2,'MAINNET_FEE_SOURCE_IMPORT_DRIFT');derived=derived.replace(before,after);}
  return derived;
}

export function mainnetFeeCoreBinding(release){
  const meta=release?.artifacts?._meta;
  check(/^[a-f0-9]{64}$/.test(release?.artifactSHA256??'')&&meta?.schema==='phase2-asp-production-build/v1'
    &&meta.releaseCandidate===true&&meta.testOnly===false&&meta.productionReady===false
    &&JSON.stringify(meta.allowedChainIds)==='[4663]'&&meta.policyMode==='asp'&&/^[a-f0-9]{64}$/.test(meta.sourceSetSHA256??''),'MAINNET_FEE_FINAL_CORE_REQUIRED');
  const ctor=release.artifacts.Phase2ASPRegistry?.abi?.find(a=>a.type==='constructor');
  check(ctor?.inputs?.length===2&&ctor.inputs.every(x=>x.type==='address')
    &&release.artifacts.Phase2ASPPool?.abi?.some(x=>x.type==='function'&&x.name==='holderExit'),'MAINNET_FEE_GUARDIAN_CORE_REQUIRED');
  const manifests={};
  for(const name of ['joinsplit','holder-exit']){
    const c=meta.circuits?.[name];
    check(c?.manifest===`protocol/phase2-mainnet/build/${name}/manifest.json`&&/^[a-f0-9]{64}$/.test(c.manifestSHA256??'')
      &&/^[a-f0-9]{64}$/.test(c.zkeySHA256??'')&&c.verifyFromR1cs===true&&c.verificationKeyBound===true
      &&c.solidityVerifierBound===true&&c.finalBeacon===true&&c.transcriptBound===true&&c.nonBeaconContributors>=2,'MAINNET_FEE_FINAL_CORE_REQUIRED');
    manifests[name]={path:c.manifest,sha256:c.manifestSHA256,zkeySHA256:c.zkeySHA256};
  }
  return {build:{path:CORE,sha256:release.artifactSHA256},sourceSetSHA256:meta.sourceSetSHA256,manifests};
}

function read(root,relative){
  check(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')
    &&relative.split('/').every(s=>s&&s!=='.'&&s!=='..'&&!s.startsWith('.')),'MAINNET_FEE_PUBLIC_PATH_REQUIRED');
  const filename=path.join(root,relative),stat=fs.lstatSync(filename);
  check(stat.isFile()&&!stat.isSymbolicLink()&&fs.realpathSync(filename)===filename&&stat.size<=8*1024*1024,'MAINNET_FEE_REGULAR_FILE_REQUIRED');
  return fs.readFileSync(filename);
}

/** Compile the precise audited source with only chain guard/import derivations. */
export function compileMainnetFeeComponent({rootDirectory,coreRelease}){
  const root=fs.realpathSync(rootDirectory),coreReleaseBinding=mainnetFeeCoreBinding(coreRelease);
  check(solc.version().startsWith('0.8.28+'),'MAINNET_FEE_COMPILER_VERSION');
  const original=read(root,AUDITED_FEE_SOURCE),derived=deriveMainnetFeeSource(original.toString('utf8'));
  const files=new Map([[AUDITED_FEE_SOURCE,original],[MAINNET_FEE_SOURCE,Buffer.from(derived)]]);
  const dep=read(root,'node_modules/@openzeppelin/contracts/package.json');
  check(JSON.parse(dep).version==='5.0.2','MAINNET_FEE_OPENZEPPELIN_VERSION');files.set('node_modules/@openzeppelin/contracts/package.json',dep);
  const sources={[MAINNET_FEE_SOURCE]:{content:derived}},input={language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:10000},viaIR:true,evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode','evm.deployedBytecode']}}}};
  const compiled=JSON.parse(solc.compile(JSON.stringify(input),{import(name){
    try{check(name.startsWith('@openzeppelin/contracts/')||IMPORTS.includes(name),'MAINNET_FEE_IMPORT_REJECTED');
      const relative=name.startsWith('@')?'node_modules/'+name:name,bytes=read(root,relative);
      if(IMPORTS.includes(name))check(coreRelease.artifacts._meta.sourceDigests?.[name]===feeSHA256(bytes),'MAINNET_FEE_CORE_INTERFACE_CHANGED');
      files.set(relative,bytes);sources[name]={content:bytes.toString('utf8')};return {contents:bytes.toString('utf8')};
    }catch(error){return {error:error.code??'MAINNET_FEE_IMPORT_FAILED'};}
  }}));
  check(!(compiled.errors??[]).some(e=>e.severity==='error'),'MAINNET_FEE_COMPILATION_FAILED');
  const contracts={};
  for(const name of MAINNET_FEE_TYPES){
    const c=compiled.contracts?.[MAINNET_FEE_SOURCE]?.[name];
    check(c?.evm?.bytecode?.object&&c.evm.bytecode.object.length/2<=49152&&c.evm.deployedBytecode.object.length/2<=24576,'MAINNET_FEE_OVERSIZED_CONTRACT');
    check(!c.abi.some(a=>a.type==='function'&&/^(owner|admin|upgrade|set|pause|grant|revoke|sweep)/i.test(a.name)),'MAINNET_FEE_PRIVILEGED_FUNCTION');
    check(c.abi.find(a=>a.type==='constructor')?.inputs?.map(a=>a.type).join(',')==='address,address,address,address,uint8,bytes,uint16,address','MAINNET_FEE_CONSTRUCTOR_INTERFACE_CHANGED');
    check(Object.keys(c.evm.bytecode.linkReferences??{}).length===0,'MAINNET_FEE_UNEXPECTED_LINKING');
    contracts[name]={source:MAINNET_FEE_SOURCE,abi:c.abi,bytecode:'0x'+c.evm.bytecode.object,deployedBytecode:'0x'+c.evm.deployedBytecode.object,
      linkReferences:c.evm.bytecode.linkReferences,deployedLinkReferences:c.evm.deployedBytecode.linkReferences,immutableReferences:c.evm.deployedBytecode.immutableReferences};
  }
  // Recompile an all-sources portable input, independently of the import callback.
  const portableInput={...input,sources:{...sources}},portable=JSON.parse(solc.compile(JSON.stringify(portableInput)));
  check(!(portable.errors??[]).some(e=>e.severity==='error'),'MAINNET_FEE_PORTABLE_COMPILATION_FAILED');
  for(const name of MAINNET_FEE_TYPES){const c=portable.contracts[MAINNET_FEE_SOURCE][name],expected=contracts[name];
    check('0x'+c.evm.bytecode.object===expected.bytecode&&'0x'+c.evm.deployedBytecode.object===expected.deployedBytecode
      &&isDeepStrictEqual(c.abi,expected.abi),'MAINNET_FEE_REPRODUCIBILITY_FAILED');
    // solc AST identifiers can differ when dependencies enter through callbacks
    // rather than explicit input. Immutable byte offsets and lengths must agree;
    // the published map comes from the self-contained portable compilation.
    const offsets=refs=>Object.values(refs??{}).flat().sort((a,b)=>a.start-b.start||a.length-b.length);
    check(isDeepStrictEqual(offsets(c.evm.deployedBytecode.immutableReferences),offsets(expected.immutableReferences)),'MAINNET_FEE_IMMUTABLE_OFFSETS_CHANGED');
    expected.immutableReferences=c.evm.deployedBytecode.immutableReferences;
  }
  const sourceEntries=[...files].map(([file,bytes])=>[file,feeSHA256(bytes)]).sort(([a],[b])=>a.localeCompare(b));
  const artifact={_meta:{schema:'phase2-fees-production-build/v1',releaseCandidate:true,experimental:false,testOnly:false,productionReady:false,deployed:false,
    allowedChainIds:[4663],compiler:solc.version(),optimizerRuns:10000,viaIR:true,evmVersion:'cancun',
    inputSHA256:feeSHA256(JSON.stringify(portableInput)),sourceDigests:Object.fromEntries(sourceEntries),sourceSetSHA256:feeSHA256(JSON.stringify(sourceEntries)),
    sourceDerivation:{source:AUDITED_FEE_SOURCE,sourceSHA256:feeSHA256(original),target:MAINNET_FEE_SOURCE,derivedSourceSHA256:feeSHA256(derived),changes:['mainnet-only-chain-guard','final-core-interface-imports']},
    coreRelease:coreReleaseBinding,adapters:[...MAINNET_FEE_TYPES],feeModel:{immutableRateAndTreasury:true,maxServiceFeeBps:100,denominator:10000,
      serviceFee:'floor(measuredGrossOutput * FEE_BPS / 10000)',minAmountOut:'net amount deposited into the target privacy pool',maxServiceFee:'proof-bound absolute maximum in TOKEN_OUT base units',nativeOutputServiceFeeAsset:'wrapped native'},
    limitations:['Release candidate only; no independent audit, public deployment or mainnet funds acceptance is implied.',
      'Binds the final core release and derived mainnet-only bytecode; never adopts development proving keys.',
      'Existing testnet artifacts and free adapters are unchanged. Route, amounts, fees and timing remain public.',
      'Treasury and fee rate are immutable constructor arguments and require a separately reviewed deployment plan.']},...contracts};
  return {artifact,portableInput,derivedSource:derived,artifactBytes:Buffer.from(json(artifact))};
}

/** Caller supplies an actually verified core release, not untrusted HTTP metadata. */
export function verifyMainnetFeeComponent({rootDirectory,artifactBytes,coreRelease}){
  const root=fs.realpathSync(rootDirectory),artifact=JSON.parse(Buffer.from(artifactBytes)),meta=artifact._meta;
  check(meta?.schema==='phase2-fees-production-build/v1'&&meta.releaseCandidate===true&&meta.experimental===false
    &&meta.testOnly===false&&meta.productionReady===false&&meta.deployed===false&&JSON.stringify(meta.allowedChainIds)==='[4663]','MAINNET_FEE_COMPONENT_NOT_PRODUCTION');
  check(isDeepStrictEqual(meta.coreRelease,mainnetFeeCoreBinding(coreRelease)),'MAINNET_FEE_CORE_RELEASE_MISMATCH');
  check(meta.sourceDigests&&Object.keys(meta.sourceDigests).length>4,'MAINNET_FEE_SOURCE_INVENTORY_REQUIRED');
  for(const [relative,digest]of Object.entries(meta.sourceDigests))check(feeSHA256(read(root,relative))===digest,'MAINNET_FEE_COMPONENT_SOURCE_CHANGED');
  // All source bytes are rechecked above and the actual final core is bound.
  // Identical public releases may live at more than one canonical root.
  const cacheKey=feeSHA256(Buffer.from(artifactBytes))+':'+solc.version();
  if(!cache.has(cacheKey)){
    const rebuilt=compileMainnetFeeComponent({rootDirectory:root,coreRelease});
    check(isDeepStrictEqual(artifact,rebuilt.artifact),'MAINNET_FEE_COMPONENT_REBUILD_MISMATCH');
    cache.set(cacheKey,true);if(cache.size>8)cache.delete(cache.keys().next().value);
  }
  return {artifactSHA256:feeSHA256(artifactBytes),sourceSetSHA256:meta.sourceSetSHA256,experimental:false,releaseCandidate:true,productionReady:false,
    coreRelease:meta.coreRelease,contracts:Object.fromEntries(MAINNET_FEE_TYPES.map(name=>[name,artifact[name]]))};
}
