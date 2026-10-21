// SPDX-License-Identifier: Apache-2.0
// Independently pinned adapter components; never replaces a pool or verifier.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {FEE_ADAPTER_TYPES} from './sdk.mjs';
import {loadProductionRelease,loadProductionRuntimeRelease} from '../phase2-mainnet/artifacts.mjs';
import {verifyMainnetFeeComponent} from './mainnet-release.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
async function regularFile(filename){
  const handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await handle.stat();need(stat.isFile()&&stat.size<=8*1024*1024&&await fs.realpath(filename)===filename,'FEE_COMPONENT_FILE_INVALID');return await handle.readFile();}finally{await handle.close();}
}
export async function loadFeeComponents({filename,rootDirectory,routes,chainId,validationScope}={}){
  const root=await fs.realpath(rootDirectory),bytes=await regularFile(path.resolve(filename)),artifact=JSON.parse(bytes),meta=artifact._meta,artifactSHA256=sha(bytes);
  const mainnet=chainId===4663;
  if(mainnet){
    // A renamed experimental bundle or flipped productionReady flag is not a
    // release. Verify the final core, derive/recompile the mainnet-only adapters,
    // and require each actual route to pin that exact component and core profile.
    need(meta?.schema==='phase2-fees-production-build/v1'&&meta.testOnly===false&&meta.releaseCandidate===true
      &&meta.productionReady===false,'MAINNET_FEE_COMPONENT_NOT_PRODUCTION');
    need(Array.isArray(routes)&&routes.length>0&&routes.every(entry=>FEE_ADAPTER_TYPES.includes(entry.route?.adapterType)
      &&entry.route.feeArtifactSHA256===artifactSHA256&&entry.targetProfile?.schema==='phase2-asp-production-profile/v1'
      &&entry.targetProfile.artifactSHA256===meta.coreRelease?.build?.sha256),'PINNED_FEE_COMPONENT_REQUIRED');
    const coreRelease=validationScope===undefined?await loadProductionRelease({rootDirectory:root,profile:routes[0].targetProfile}):await loadProductionRuntimeRelease({rootDirectory:root,profile:routes[0].targetProfile,validationScope});
    return verifyMainnetFeeComponent({rootDirectory:root,artifactBytes:bytes,coreRelease});
  }
  const release=meta?.experimental===true&&meta.testOnly===true&&meta.productionReady===false&&meta.deployed===false;
  need(release&&meta.allowedChainIds?.includes(chainId)&&meta.feeModel?.immutableRateAndTreasury===true,
    mainnet&&meta?.testOnly!==false?'MAINNET_FEE_COMPONENT_NOT_PRODUCTION':'INVALID_FEE_COMPONENT_BUILD');
  need(Array.isArray(routes)&&routes.length>0&&routes.every(entry=>FEE_ADAPTER_TYPES.includes(entry.route?.adapterType)
    &&entry.route.feeArtifactSHA256===artifactSHA256),'PINNED_FEE_COMPONENT_REQUIRED');
  need(meta.sourceDigests&&Object.keys(meta.sourceDigests).length>0,'FEE_COMPONENT_SOURCES_REQUIRED');
  const entries=Object.entries(meta.sourceDigests);
  need(sha(JSON.stringify(entries))===meta.sourceSetSHA256,'FEE_COMPONENT_SOURCE_SET_MISMATCH');
  for(const [relative,digest]of entries){
    need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.split(/[\\/]/).includes('..')&&/^[a-f0-9]{64}$/.test(digest),'FEE_COMPONENT_SOURCE_INVALID');
    const absolute=path.resolve(root,relative);need(absolute.startsWith(root+path.sep),'FEE_COMPONENT_SOURCE_INVALID');
    need(sha(await regularFile(absolute))===digest,'FEE_COMPONENT_SOURCE_CHANGED');
  }
  const contracts={};
  for(const type of FEE_ADAPTER_TYPES){
    const contract=artifact[type];need(Array.isArray(contract?.abi)&&/^0x[0-9a-f]+$/i.test(contract.bytecode??'')&&/^0x[0-9a-f]+$/i.test(contract.deployedBytecode??''),'FEE_COMPONENT_CONTRACT_REQUIRED');
    contracts[type]=contract;
  }
  return {artifactSHA256,sourceSetSHA256:meta.sourceSetSHA256,experimental:!mainnet,productionReady:mainnet,contracts};
}
