#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Offline audit of the exact mainnet source allowlist; never reads runtime mounts.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {contextFiles} from '../phase2-asp-context.mjs';
const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function auditMainnetContext({root=ROOT}={}){
  root=await fs.realpath(root);
  const dockerfile=await fs.readFile(path.join(root,'docker/mainnet/runtime.Dockerfile'),'utf8');
  const pins=JSON.parse(await fs.readFile(path.join(root,'docker/image-pins.json'),'utf8'));
  need(dockerfile.includes(`ARG NODE_IMAGE=${pins.node.image}@${pins.node.indexDigest}`)
    &&dockerfile.includes(`ARG FOUNDRY_IMAGE=${pins.foundry.image}@${pins.foundry.indexDigest}`),'MAINNET_CONTAINER_IMAGE_PIN_MISMATCH');
  need(dockerfile.includes('COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast')
    &&dockerfile.includes('USER 10001:10001')&&dockerfile.includes('LINCOLN_MAINNET_SIGNING_ENABLED=0'),'MAINNET_CONTAINER_RUNTIME_GUARD_MISSING');
  const ignore=await fs.readFile(path.join(root,'docker/mainnet/runtime.Dockerfile.dockerignore'),'utf8'),files=contextFiles(ignore),allowed=new Set(files),records=[];
  need(['package.json','package-lock.json','docker/mainnet/start.mjs','src/phase2-mainnet/server.mjs','src/phase2-mainnet/release.mjs','src/phase2-mainnet/signer.mjs','src/phase2-mainnet/rpc.mjs'].every(f=>allowed.has(f)),'MAINNET_CONTAINER_RUNTIME_IMPORT_MISSING');
  for(const file of files){
    need(!/^(artifacts|config|protocol|vendor)\//.test(file)&&!/^scripts\/(?:aws|private-transfer)\//.test(file),'MAINNET_CONTAINER_MOUNT_DATA_INCLUDED');
    const absolute=path.join(root,file),stat=await fs.lstat(absolute);
    need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(absolute)===absolute,'MAINNET_CONTAINER_REGULAR_SOURCE_REQUIRED');
    const bytes=await fs.readFile(absolute);records.push({file,bytes:bytes.length,sha256:sha(bytes)});
    if(file.endsWith('.mjs')){
      const source=bytes.toString('utf8'),imports=[...source.matchAll(/\b(?:import|export)\s+(?:[^'";]+?\s+from\s+)?['"](\.[^'"]+)['"]/g),...source.matchAll(/\bimport\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g)];
      for(const match of imports){const target=path.posix.normalize(path.posix.join(path.posix.dirname(file),match[1]));need(allowed.has(target),`MAINNET_CONTAINER_MISSING_IMPORT:${target}`);}
    }
  }
  return {schema:'lincoln-mainnet-container-context/v1',ok:true,chainId:4663,files:records,contextBytes:records.reduce((sum,f)=>sum+f.bytes,0),
    contextSHA256:sha(JSON.stringify(records)),dockerfileSHA256:sha(dockerfile),ignoreSHA256:sha(ignore),secretsIncluded:false,provingParametersIncluded:false,
    castPinned:true,signingDefault:false,productionReleaseRequiredAtStartup:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))auditMainnetContext().then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(e.code??e.message);process.exitCode=1;});
