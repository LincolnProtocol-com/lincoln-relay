// SPDX-License-Identifier: Apache-2.0
// Final parameter and reproducible-bytecode gate shared by deployment/startup.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {buildMainnetSourcePlan,loadFinalProductionCircuit,verifyFinalProductionCircuit,compileMainnetSources} from '../../scripts/phase2-mainnet/build.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
export const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
export async function readPublicFile(root,relative){
  need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!p.startsWith('.')),'MAINNET_PUBLIC_PATH_REQUIRED');
  const file=path.join(root,relative),stat=await fs.lstat(file);
  need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(file)===file,'MAINNET_REGULAR_FILE_REQUIRED');return fs.readFile(file);
}
export async function loadVerifiedMainnetRelease({root=ROOT}={}){
  root=await fs.realpath(root);
  const config=JSON.parse(await readPublicFile(root,'config/phase2-mainnet.json'));
  need(config.enabled===true&&config.chain?.id===4663&&config.network==='mainnet'&&config.deployment?.policyMode==='asp'
    &&config.deployment.selected==='aspSelfHosted','MAINNET_DEPLOYMENT_TARGET_INVALID');
  const circuits={};
  try{
    for(const name of ['joinsplit','holder-exit']){
      const circuit=await loadFinalProductionCircuit({root,name});
      circuit.verified=await verifyFinalProductionCircuit(circuit,{root});circuits[name]=circuit;
    }
    const artifactPath=config.productionArtifacts.build,artifactBytes=await readPublicFile(root,artifactPath),artifacts=JSON.parse(artifactBytes),meta=artifacts._meta;
    need(meta?.schema==='phase2-asp-production-build/v1'&&meta.testOnly===false&&meta.releaseCandidate===true
      &&JSON.stringify(meta.allowedChainIds)==='[4663]'&&meta.policyMode==='asp','MAINNET_DEPLOYMENT_BUILD_REJECTED');
    const sourcePlan=await buildMainnetSourcePlan({root}),sources={};
    for(const item of sourcePlan.sources){
      const source=(await readPublicFile(root,item.target)).toString('utf8');
      need(sha256(source)===item.derivedGuardSourceSHA256,'MAINNET_DEPLOYMENT_DERIVED_SOURCE_MISMATCH');sources[item.target]=source;
    }
    for(const c of Object.values(circuits)){
      need(meta.circuits?.[c.name]?.manifestSHA256===c.manifestSHA256&&meta.circuits[c.name].zkeySHA256===sha256(c.files.zkey.bytes),'MAINNET_DEPLOYMENT_CIRCUIT_BINDING_MISMATCH');
      sources[c.files.verifier.path]=c.files.verifier.bytes.toString('utf8');
    }
    const compiled=await compileMainnetSources({root,sources});
    need(compiled.sourceSetSHA256===meta.sourceSetSHA256&&compiled.inputSHA256===meta.inputSHA256
      &&isDeepStrictEqual(compiled.sourceDigests,meta.sourceDigests),'MAINNET_DEPLOYMENT_COMPILER_INPUT_MISMATCH');
    need(isDeepStrictEqual(Object.keys(artifacts).filter(k=>k!=='_meta').sort(),Object.keys(compiled.contracts).sort()),'MAINNET_DEPLOYMENT_CONTRACT_SET_MISMATCH');
    for(const [name,contract]of Object.entries(compiled.contracts))need(isDeepStrictEqual(contract,artifacts[name]),'MAINNET_DEPLOYMENT_BYTECODE_MISMATCH');
    const production={build:{path:artifactPath,sha256:sha256(artifactBytes)},manifests:{},parameters:{}};
    for(const c of Object.values(circuits)){
      production.manifests[c.name]={path:c.manifestPath,sha256:c.manifestSHA256};
      production.parameters[c.name]=Object.fromEntries(Object.entries(c.files).map(([kind,file])=>[kind,{path:file.path,sha256:sha256(file.bytes)}]));
    }
    production.releaseId=production.build.sha256;
    return {config,artifacts,artifactSHA256:production.build.sha256,sourceSetSHA256:meta.sourceSetSHA256,production};
  }finally{
    if(globalThis.curve_bn128){await globalThis.curve_bn128.terminate();globalThis.curve_bn128=undefined;}
  }
}
