// SPDX-License-Identifier: Apache-2.0
// Same-host blue/green control only. No HTTP endpoint can grant writer ownership.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {createHash,randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {openServiceStore} from '../phase1-service/store.mjs';

export const MAINNET_ACTIVATION_DIRECTORY='/run/lincoln-mainnet-activation';
export const MAINNET_PREPARED_DIRECTORY='/run/lincoln-mainnet-prepared';
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=value=>createHash('sha256').update(value).digest('hex');
const digest=value=>sha(JSON.stringify(value));
const HASH=/^[a-f0-9]{64}$/;
const exact=(value,keys,code)=>need(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(','),code);
const seconds=()=>Math.floor(Date.now()/1000);
const bindingKeys=['role','challenge','releaseSHA256','configurationSHA256'];

async function regularBytes(filename,{maxBytes=8*1024*1024,ownerUID,secure=false}={}){
  const h=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const stat=await h.stat();
    need(stat.isFile()&&stat.nlink===1&&stat.size<=maxBytes&&await fs.realpath(filename)===filename,'MAINNET_ACTIVATION_REGULAR_FILE_REQUIRED');
    if(ownerUID!==undefined)need(stat.uid===ownerUID&&(stat.mode&0o022)===0,'MAINNET_ACTIVATION_ROOT_CONTROL_REQUIRED');
    if(secure)need((stat.mode&0o077)===0,'MAINNET_ACTIVATION_PRIVATE_STATE_REQUIRED');
    return await h.readFile();
  }finally{await h.close();}
}
async function trustedDirectory(directory,ownerUID){
  const stat=await fs.lstat(directory);
  need(stat.isDirectory()&&!stat.isSymbolicLink()&&await fs.realpath(directory)===directory&&stat.uid===ownerUID&&(stat.mode&0o022)===0,'MAINNET_ACTIVATION_ROOT_CONTROL_REQUIRED');
  return {dev:stat.dev,ino:stat.ino};
}
function validateBinding(value){
  need(['apis','api','asp'].includes(value.role)&&bindingKeys.slice(1).every(k=>HASH.test(value[k]??'')),'MAINNET_ACTIVATION_BINDING_INVALID');
}
function assertSameBinding(a,b){need(bindingKeys.every(key=>a[key]===b[key]),'MAINNET_ACTIVATION_BINDING_MISMATCH');}

/** Entire public config mount, not only runtime.json. Sorting uses code-point
 * order so a host controller can reproduce the exact digest without Node.
 */
export async function readMainnetConfigurationDigest(directory){
  need(path.isAbsolute(directory)&&await fs.realpath(directory)===directory,'MAINNET_ACTIVATION_CONFIG_DIRECTORY_INVALID');
  const files=[];let directories=0;
  async function walk(absolute,relative=''){
    const stat=await fs.lstat(absolute);
    need(stat.isDirectory()&&!stat.isSymbolicLink()&&await fs.realpath(absolute)===absolute&&(stat.mode&0o022)===0&&++directories<=256,'MAINNET_ACTIVATION_CONFIG_DIRECTORY_INVALID');
    for(const name of (await fs.readdir(absolute)).sort()){
      need(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(name),'MAINNET_ACTIVATION_CONFIG_INVENTORY_INVALID');
      const filename=path.join(absolute,name),entry=await fs.lstat(filename),ref=relative?`${relative}/${name}`:name;
      need(!entry.isSymbolicLink(),'MAINNET_ACTIVATION_REGULAR_FILE_REQUIRED');
      if(entry.isDirectory())await walk(filename,ref);
      else{
        need(entry.isFile()&&(entry.mode&0o022)===0&&/\.(json|env)$/.test(name)&&files.length<256,'MAINNET_ACTIVATION_CONFIG_INVENTORY_INVALID');
        const bytes=await regularBytes(filename);
        if(name.endsWith('.json'))JSON.parse(bytes);
        files.push({path:ref,sha256:sha(bytes)});
      }
    }
  }
  await walk(directory);
  need(files.length>0,'MAINNET_ACTIVATION_CONFIG_INVENTORY_INVALID');
  files.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  return {configurationSHA256:digest(files),files};
}

export async function readMainnetActivationRequest({role,configurationSHA256,directory=MAINNET_ACTIVATION_DIRECTORY,ownerUID=0,now=seconds}={}){
  const directoryIdentity=await trustedDirectory(directory,ownerUID),request=JSON.parse(await regularBytes(path.join(directory,'request.json'),{ownerUID}));
  exact(request,['schema',...bindingKeys,'expiresAt',...(Object.hasOwn(request,'appendMigration')?['appendMigration']:[])],'MAINNET_ACTIVATION_REQUEST_INVALID');
  validateBinding(request);
  need(request.schema==='lincoln-mainnet-activation-request/v1'&&request.role===role&&request.configurationSHA256===configurationSHA256,'MAINNET_ACTIVATION_BINDING_MISMATCH');
  need(Number.isSafeInteger(request.expiresAt)&&request.expiresAt>now()&&request.expiresAt<=now()+3600,'MAINNET_ACTIVATION_REQUEST_EXPIRED');
  if(request.appendMigration){
    const migration=request.appendMigration;
    exact(migration,['schema','previousConfigurationSHA256','configurationSHA256','existingPoolIds','initializePoolIds'],'MAINNET_ACTIVATION_APPEND_INVALID');
    need(role==='apis'&&migration.schema==='lincoln-mainnet-api-store-append/v1'&&HASH.test(migration.previousConfigurationSHA256??'')
      &&migration.previousConfigurationSHA256!==configurationSHA256&&migration.configurationSHA256===configurationSHA256
      &&JSON.stringify(migration.existingPoolIds)===JSON.stringify(['eth','usdg','nvda','spy','meta','tsla','googl','qqq','mstr'])
      &&JSON.stringify(migration.initializePoolIds)===JSON.stringify(['aapl','usde','pons','cashcat']),'MAINNET_ACTIVATION_APPEND_INVALID');
  }
  return {request,directoryIdentity};
}

async function publishPrepared(directory,value){
  const stat=await fs.lstat(directory);
  need(stat.isDirectory()&&!stat.isSymbolicLink()&&await fs.realpath(directory)===directory&&(stat.mode&0o022)===0,'MAINNET_ACTIVATION_STATUS_DIRECTORY_INVALID');
  const temporary=path.join(directory,`.prepared-${randomBytes(16).toString('hex')}.tmp`),h=await fs.open(temporary,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await h.writeFile(JSON.stringify(value)+'\n');await h.sync();}finally{await h.close();}
  try{await fs.rename(temporary,path.join(directory,'prepared.json'));}finally{await fs.unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;});}
}

/** Call only after full preparation. No business store is touched while waiting.
 * The root-controlled gate is bound to this one process's completed preparation;
 * old gates, another role or modified inputs cannot activate a candidate.
 */
export async function waitForMainnetActivation({request,directoryIdentity,directory=MAINNET_ACTIVATION_DIRECTORY,statusDirectory=MAINNET_PREPARED_DIRECTORY,
  ownerUID=0,signal,now=seconds,pollMilliseconds=250,verifyInputs,onPrepared=()=>{}}={}){
  need(typeof verifyInputs==='function'&&Number.isSafeInteger(pollMilliseconds)&&pollMilliseconds>=10&&pollMilliseconds<=5000,'MAINNET_ACTIVATION_OPTIONS_INVALID');
  const body={schema:'lincoln-mainnet-prepared/v1',...Object.fromEntries(bindingKeys.map(k=>[k,request[k]])),processChallenge:randomBytes(32).toString('hex'),preparedAt:now()},prepared={...body,preparedSHA256:digest(body)};
  await publishPrepared(statusDirectory,prepared);await onPrepared(prepared);
  for(;;){
    need(!signal?.aborted,'MAINNET_ACTIVATION_ABORTED');
    need(now()<request.expiresAt,'MAINNET_ACTIVATION_REQUEST_EXPIRED');
    const currentDirectory=await trustedDirectory(directory,ownerUID);
    need(currentDirectory.dev===directoryIdentity.dev&&currentDirectory.ino===directoryIdentity.ino,'MAINNET_ACTIVATION_DIRECTORY_CHANGED');
    const currentRequest=JSON.parse(await regularBytes(path.join(directory,'request.json'),{ownerUID}));
    need(JSON.stringify(currentRequest)===JSON.stringify(request),'MAINNET_ACTIVATION_REQUEST_CHANGED');
    let activation;
    try{activation=JSON.parse(await regularBytes(path.join(directory,'activate.json'),{ownerUID}));}catch(error){if(error.code!=='ENOENT')throw error;}
    if(activation){
      exact(activation,['schema',...bindingKeys,'preparedSHA256','issuedAt'],'MAINNET_ACTIVATION_GATE_INVALID');
      assertSameBinding(activation,request);
      need(activation.schema==='lincoln-mainnet-activate/v1'&&activation.preparedSHA256===prepared.preparedSHA256,'MAINNET_ACTIVATION_PREPARATION_MISMATCH');
      need(Number.isSafeInteger(activation.issuedAt)&&activation.issuedAt<=now()&&activation.issuedAt>=now()-300,'MAINNET_ACTIVATION_GATE_EXPIRED');
      await verifyInputs();
      need(!signal?.aborted&&now()<request.expiresAt,'MAINNET_ACTIVATION_ABORTED');
      // Revalidation can take seconds. A host operator may revoke the grant in
      // that interval, so do not activate from an already removed/replaced gate.
      const finalDirectory=await trustedDirectory(directory,ownerUID);
      need(finalDirectory.dev===directoryIdentity.dev&&finalDirectory.ino===directoryIdentity.ino,'MAINNET_ACTIVATION_DIRECTORY_CHANGED');
      need(JSON.stringify(JSON.parse(await regularBytes(path.join(directory,'request.json'),{ownerUID})))===JSON.stringify(request),'MAINNET_ACTIVATION_REQUEST_CHANGED');
      need(JSON.stringify(JSON.parse(await regularBytes(path.join(directory,'activate.json'),{ownerUID})))===JSON.stringify(activation),'MAINNET_ACTIVATION_GATE_CHANGED');
      need(activation.issuedAt>=now()-300,'MAINNET_ACTIVATION_GATE_EXPIRED');
      return prepared;
    }
    try{await delay(pollMilliseconds,undefined,{signal});}catch(error){if(error.name==='AbortError')throw Object.assign(new Error('MAINNET_ACTIVATION_ABORTED'),{code:'MAINNET_ACTIVATION_ABORTED'});throw error;}
  }
}

async function noLock(directory){
  need(await fs.realpath(directory)===directory,'MAINNET_ACTIVATION_STATE_DIRECTORY_INVALID');
  try{await fs.lstat(path.join(directory,'.service.lock'));throw Object.assign(new Error('MAINNET_ACTIVATION_STORE_LOCKED'),{code:'MAINNET_ACTIVATION_STORE_LOCKED'});}
  catch(error){if(error.code!=='ENOENT')throw error;}
}
async function readJournal(directory,filename){
  await noLock(directory);
  const envelope=JSON.parse(await regularBytes(path.join(directory,filename),{maxBytes:128*1024*1024,secure:true}));
  exact(envelope,['schema','identity','value','digest'],'MAINNET_ACTIVATION_STATE_CORRUPT');
  const {digest:expected,...body}=envelope;
  need(envelope.schema==='phase1-service-store/v1'&&typeof envelope.identity==='string'&&expected===digest(body),'MAINNET_ACTIVATION_STATE_CORRUPT');
  return envelope.value;
}
const settled=status=>['confirmed','reverted','cancelled'].includes(status);

/** Role-local quiescence. API promotion must not stop or inspect ASP's lifecycle
 * store, and ASP promotion must not interfere with the relay's separate address.
 * This is an extra handoff check; existing store locks still enforce ownership.
 * Missing journals fail closed: a first-ever deployment uses the cold path.
 */
export async function assertMainnetRoleQuiescent({role,stateDirectory,poolIds,address,initialPoolIds=[]}={}){
  need(['apis','api','asp'].includes(role)&&Array.isArray(poolIds)&&poolIds.length>0&&/^0x[0-9a-f]{40}$/i.test(address??''),'MAINNET_ACTIVATION_STATE_OPTIONS_INVALID');
  need(Array.isArray(initialPoolIds)&&(!initialPoolIds.length||role==='apis'
    &&JSON.stringify(initialPoolIds)===JSON.stringify(['aapl','usde','pons','cashcat'])
    &&JSON.stringify(poolIds)===JSON.stringify(['eth','usdg','nvda','spy','meta','tsla','googl','qqq','mstr',...initialPoolIds])),'MAINNET_ACTIVATION_APPEND_INVALID');
  if(role==='asp'){
    const journal=await readJournal(path.join(stateDirectory,'asp/operator'),'operator.json');
    need(journal.schema==='phase2-asp-operator-journal/v1'&&Array.isArray(journal.jobs)&&journal.jobs.every(job=>['confirmed','reverted','superseded'].includes(job.state)),'MAINNET_ACTIVATION_ASP_NOT_DRAINED');
  }else for(const id of poolIds){
    need(/^[a-z][a-z0-9_-]{0,63}$/.test(id),'MAINNET_ACTIVATION_STATE_OPTIONS_INVALID');
    const directory=path.join(stateDirectory,'api',id);
    if(initialPoolIds.includes(id)){
      try{await fs.lstat(directory);throw Object.assign(new Error('MAINNET_ACTIVATION_APPEND_STATE_ALREADY_EXISTS'),{code:'MAINNET_ACTIVATION_APPEND_STATE_ALREADY_EXISTS'});}
      catch(error){if(error.code!=='ENOENT')throw error;}
      continue;
    }
    await noLock(path.join(directory,'indexer'));
    const journal=await readJournal(path.join(directory,'relay'),'jobs.json');
    need(journal.schema==='phase2-mainnet-relay-jobs/v1'&&Array.isArray(journal.jobs)&&journal.jobs.every(job=>settled(job.status)),'MAINNET_ACTIVATION_RELAY_NOT_DRAINED');
  }
  const signer=await readJournal(path.join(stateDirectory,'signers',`4663-${address.toLowerCase()}`),'signer.json');
  need(signer.schema==='phase2-mainnet-signer/v1'&&signer.chainId===4663&&signer.address?.toLowerCase()===address.toLowerCase()
    &&Array.isArray(signer.entries)&&signer.entries.every(entry=>settled(entry.status)),'MAINNET_ACTIVATION_SIGNER_NOT_DRAINED');
  return {role,drained:true,automaticResend:false};
}

/** One lifetime lease per role on the existing shared LOCAL filesystem. A crash
 * intentionally leaves a lock for operator recovery. Never use on another host.
 */
export async function acquireMainnetWriterLease({role,stateDirectory,preparedSHA256}={}){
  need(['apis','api','asp'].includes(role)&&HASH.test(preparedSHA256??''),'MAINNET_ACTIVATION_LEASE_OPTIONS_INVALID');
  return openServiceStore({directory:path.join(stateDirectory,'runtime-writers',role==='api'?'apis':role),identity:`lincoln-mainnet-runtime-writer:4663:${role==='api'?'apis':role}`,filename:'lease.json'});
}
