// SPDX-License-Identifier: Apache-2.0
// Public process telemetry only. Never authorizes a policy, a signature or a spend.
import fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';

const HASH=/^0x[0-9a-f]{64}$/i,ADDRESS=/^0x[0-9a-f]{40}$/i;
const STATUSES=new Set(['running','paused','blocked','unknown']);
export const PUBLISHER_HEARTBEAT_SCHEMA='phase2-asp-publisher-heartbeat/v1';
export const PUBLISHER_PUBLIC_REASONS=Object.freeze([
  'ASP_PUBLISHER_RUNNING','ASP_PUBLISHER_STARTING','ASP_PUBLISHER_STATUS_ONLY',
  'ASP_PUBLISHER_STOPPED','ASP_PUBLISHER_ONCE_COMPLETE','ASP_PUBLISHER_ITERATION_LIMIT',
  'ASP_PUBLISHER_BUDGET_EXHAUSTED','ASP_PUBLISHER_BROADCAST_UNKNOWN','ASP_PUBLISHER_ROOT_PENDING',
  'ASP_PUBLISHER_AWAITING_CONFIRMATIONS','ASP_PUBLISHER_RPC_UNAVAILABLE','ASP_PUBLISHER_SIGNER_BUSY','ASP_PUBLISHER_ERROR',
  'ASP_PUBLISHER_NOT_CONFIGURED','ASP_PUBLISHER_HEARTBEAT_MISSING','ASP_PUBLISHER_HEARTBEAT_INVALID',
  'ASP_PUBLISHER_HEARTBEAT_UNAVAILABLE','ASP_PUBLISHER_HEARTBEAT_STALE',
]);
const REASONS=new Set(PUBLISHER_PUBLIC_REASONS);
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const interval=value=>Number.isSafeInteger(value)&&value>0&&value<=30*86400;
const quantity=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value);
const clone=value=>structuredClone(value);
export const publicMirrorURL=value=>{if(typeof value!=='string'||!value.endsWith('/')||value.length>2048)return false;try{const url=new URL(value);return url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash&&url.href===value;}catch{return false;}};
/** Bounded public GET of a JSON document from a mirror; never authoritative. */
export async function fetchPublicJSON(fetchImpl,url,maxBytes,{timeoutMs=10000}={}){
  const fail=code=>Object.assign(new Error(code),{code});
  let response;
  try{response=await fetchImpl(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(timeoutMs),headers:{accept:'application/json'}});}
  catch{throw fail('MIRROR_UNAVAILABLE');}
  if(response.status===404||response.status===403)throw fail('MIRROR_NOT_FOUND');
  if(!response.ok)throw fail('MIRROR_UNAVAILABLE');
  const declared=response.headers?.get?.('content-length');
  if(declared!==null&&declared!==undefined&&(!/^[0-9]+$/.test(declared)||Number(declared)>maxBytes))throw fail('MIRROR_TOO_LARGE');
  const text=await response.text();
  if(Buffer.byteLength(text)>maxBytes)throw fail('MIRROR_TOO_LARGE');
  try{return JSON.parse(text);}catch{throw fail('MIRROR_INVALID');}
}
const unknown=(reason,freshness,minPublishIntervalSeconds=null)=>({lastPublicationTimestamp:null,minPublishIntervalSeconds,
  publisher:{status:'unknown',reason,checkedAt:null,freshness:{status:freshness,ageSeconds:null,staleAfterSeconds:null}}});
export const DEFAULT_PUBLISHER_STATUS=Object.freeze({lastPublicationTimestamp:null,minPublishIntervalSeconds:null,
  publisher:Object.freeze({status:'unknown',reason:'ASP_PUBLISHER_NOT_CONFIGURED',checkedAt:null,
    freshness:Object.freeze({status:'unconfigured',ageSeconds:null,staleAfterSeconds:null})})});

/** Whitelisted public heartbeat. Arbitrary operator errors/journals are not copied. */
export function publisherHeartbeat({chainId,registry,status,reason,checkedAt,pollIntervalSeconds,heartbeatIntervalSeconds,minPublishIntervalSeconds}){
  check(Number.isSafeInteger(chainId)&&chainId>0&&ADDRESS.test(registry)&&STATUSES.has(status)&&REASONS.has(reason)
    &&typeof checkedAt==='string'&&Number.isFinite(Date.parse(checkedAt))&&new Date(checkedAt).toISOString()===checkedAt
    &&Number.isSafeInteger(pollIntervalSeconds)&&pollIntervalSeconds>=5&&pollIntervalSeconds<=86400
    &&Number.isSafeInteger(heartbeatIntervalSeconds)&&heartbeatIntervalSeconds>=1&&heartbeatIntervalSeconds<=30
    &&interval(minPublishIntervalSeconds),'INVALID_ASP_PUBLISHER_HEARTBEAT');
  return {schema:PUBLISHER_HEARTBEAT_SCHEMA,chainId,registry:registry.toLowerCase(),status,reason,checkedAt,
    pollIntervalSeconds,heartbeatIntervalSeconds,minPublishIntervalSeconds};
}

/** Read only an operator-configured local public heartbeat; failures stay telemetry. */
export function createPublisherStatusLoader({filename,mirrorURL,fetchImpl=globalThis.fetch,client,profile,minPublishIntervalSeconds=null,now=Date.now}={}){
  check((filename===undefined||typeof filename==='string'&&filename.length>0)&&typeof now==='function'
    &&(minPublishIntervalSeconds===null||interval(minPublishIntervalSeconds)),'INVALID_ASP_PUBLISHER_STATUS_SETTINGS');
  check(mirrorURL===undefined||publicMirrorURL(mirrorURL)&&typeof fetchImpl==='function','INVALID_ASP_PUBLISHER_STATUS_MIRROR');
  const configured=filename!==undefined||mirrorURL!==undefined,pool=profile?.pool?.address?.toLowerCase(),registry=profile?.registry?.address?.toLowerCase(),chainId=profile?.chain?.id;
  check(ADDRESS.test(pool)&&ADDRESS.test(registry)&&Number.isSafeInteger(chainId)&&chainId>0,'INVALID_ASP_PUBLISHER_STATUS_PROFILE');
  const resolved=filename!==undefined?path.resolve(filename):null,timestamps=new Map();
  let current=unknown('ASP_PUBLISHER_NOT_CONFIGURED','unconfigured',minPublishIntervalSeconds);
  function project(raw){
    check(raw?.schema===PUBLISHER_HEARTBEAT_SCHEMA,'INVALID_HEARTBEAT_FILE');
    const record=publisherHeartbeat(raw);
    check(record.chainId===chainId&&record.registry===registry
      &&(minPublishIntervalSeconds===null||record.minPublishIntervalSeconds===minPublishIntervalSeconds),'INVALID_HEARTBEAT_FILE');
    const ageMs=Number(now())-Date.parse(record.checkedAt);check(Number.isFinite(ageMs)&&ageMs>=-5000,'INVALID_HEARTBEAT_FILE');
    const ageSeconds=Math.max(0,Math.floor(ageMs/1000)),staleAfterSeconds=Math.max(30,3*record.heartbeatIntervalSeconds),stale=ageMs>staleAfterSeconds*1000;
    // A stopped process cannot keep reporting running through a stale file.
    // Terminal paused/blocked records remain last-known facts, explicitly stale.
    return {lastPublicationTimestamp:null,minPublishIntervalSeconds:record.minPublishIntervalSeconds,
      publisher:{status:stale&&record.status==='running'?'unknown':record.status,
        reason:stale&&record.status==='running'?'ASP_PUBLISHER_HEARTBEAT_STALE':record.reason,checkedAt:record.checkedAt,
        freshness:{status:stale?'stale':'fresh',ageSeconds,staleAfterSeconds}}};
  }
  async function readLocalHeartbeat(){
    let handle;
    try{
      handle=await fs.open(resolved,constants.O_RDONLY|constants.O_NOFOLLOW);
      const stat=await handle.stat();check(stat.isFile()&&stat.size<=16384&&await fs.realpath(resolved)===resolved,'INVALID_HEARTBEAT_FILE');
      return project(JSON.parse(await handle.readFile('utf8')));
    }catch(error){
      if(error.code==='ENOENT')return unknown('ASP_PUBLISHER_HEARTBEAT_MISSING','missing',minPublishIntervalSeconds);
      if(['EACCES','EPERM','EIO'].includes(error.code))return unknown('ASP_PUBLISHER_HEARTBEAT_UNAVAILABLE','unavailable',minPublishIntervalSeconds);
      return unknown('ASP_PUBLISHER_HEARTBEAT_INVALID','invalid',minPublishIntervalSeconds);
    }finally{await handle?.close().catch(()=>{});}
  }
  // The public mirror is a copy of the same heartbeat. The same freshness
  // window applies, so a lagging mirror reports unknown rather than running.
  async function readMirrorHeartbeat(){
    try{return project(await fetchPublicJSON(fetchImpl,mirrorURL+'heartbeat.json',16384));}
    catch(error){return unknown(error.code==='MIRROR_NOT_FOUND'?'ASP_PUBLISHER_HEARTBEAT_MISSING':error.code==='MIRROR_UNAVAILABLE'?'ASP_PUBLISHER_HEARTBEAT_UNAVAILABLE':'ASP_PUBLISHER_HEARTBEAT_INVALID',
      error.code==='MIRROR_NOT_FOUND'?'missing':error.code==='MIRROR_UNAVAILABLE'?'unavailable':'invalid',minPublishIntervalSeconds);}
  }
  async function readHeartbeat(){
    if(!configured)return unknown('ASP_PUBLISHER_NOT_CONFIGURED','unconfigured',minPublishIntervalSeconds);
    const local=filename===undefined?null:await readLocalHeartbeat();
    if(local&&local.publisher.status!=='unknown'||mirrorURL===undefined)return local;
    const mirrored=await readMirrorHeartbeat();
    // A mirrored record, fresh or stale, beats a missing local file; a mirror
    // that has no record falls back to the local diagnosis.
    return ['fresh','stale'].includes(mirrored.publisher.freshness.status)||local===null?mirrored:local;
  }
  async function publicationTimestamp(snapshot){
    try{
      check(snapshot?.chainId===chainId&&snapshot.pool?.toLowerCase()===pool&&Array.isArray(snapshot.policies),'INVALID_PUBLISHER_STATE');
      const event=snapshot.policies.at(-1);if(!event)return null;
      check(quantity(event.blockNumber)&&HASH.test(event.blockHash)&&quantity(snapshot.blockNumber)
        &&BigInt(event.blockNumber)<=BigInt(snapshot.blockNumber)&&event.epoch===(snapshot.asp?.latestPolicy?.epoch??snapshot.asp?.epoch),'INVALID_PUBLISHER_STATE');
      const key=`${event.blockNumber}:${event.blockHash.toLowerCase()}`;
      if(timestamps.has(key))return timestamps.get(key);
      let timestamp;
      if(event.blockNumber===snapshot.blockNumber){check(event.blockHash===snapshot.blockHash&&quantity(snapshot.blockTimestamp),'INVALID_PUBLISHER_STATE');timestamp=snapshot.blockTimestamp;}
      else{
        check(typeof client?.getBlock==='function','PUBLISHER_TIMESTAMP_RPC_REQUIRED');
        const block=await client.getBlock({blockNumber:BigInt(event.blockNumber)});
        check(block?.hash?.toLowerCase()===event.blockHash.toLowerCase()&&typeof block.timestamp==='bigint'&&block.timestamp>=0n,'PUBLISHER_TIMESTAMP_BLOCK_MISMATCH');
        timestamp=String(block.timestamp);
      }
      // Cache by authenticated block hash, never by epoch or an expiry heuristic.
      timestamps.set(key,timestamp);if(timestamps.size>32)timestamps.delete(timestamps.keys().next().value);
      return timestamp;
    }catch{return null;}
  }
  function cachedProjection(){
    const value=clone(current),publisher=value.publisher;
    if(publisher.checkedAt===null||publisher.freshness.staleAfterSeconds===null)return value;
    const ageMs=Number(now())-Date.parse(publisher.checkedAt);
    if(!Number.isFinite(ageMs)||ageMs< -5000){
      value.publisher={status:'unknown',reason:'ASP_PUBLISHER_HEARTBEAT_INVALID',checkedAt:null,
        freshness:{status:'invalid',ageSeconds:null,staleAfterSeconds:null}};return value;
    }
    publisher.freshness.ageSeconds=Math.max(0,Math.floor(ageMs/1000));
    if(ageMs>publisher.freshness.staleAfterSeconds*1000){
      publisher.freshness.status='stale';
      if(publisher.status==='running'){publisher.status='unknown';publisher.reason='ASP_PUBLISHER_HEARTBEAT_STALE';}
    }
    return value;
  }
  const loader=async snapshot=>{
    try{
      const [status,lastPublicationTimestamp]=await Promise.all([readHeartbeat(),publicationTimestamp(snapshot)]);
      current={...status,lastPublicationTimestamp};return cachedProjection();
    }catch{current=unknown('ASP_PUBLISHER_HEARTBEAT_UNAVAILABLE','unavailable',minPublishIntervalSeconds);return clone(current);}
  };
  // Synchronous service.config() callers must also age the cached heartbeat;
  // stopping all async polling must never freeze a process in running/fresh.
  loader.snapshot=cachedProjection;return loader;
}
