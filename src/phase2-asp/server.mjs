#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Wallet } from 'ethers';
import { privateKeyToAccount } from 'viem/accounts';
import { createPublicClient, http } from 'viem';
import { createPhase2ASPService } from './service.mjs';
import { normalizeProfile, associationSetDigest } from './sdk.mjs';
import { phase2Tree } from './state.mjs';
import { createNetworkPolicy } from '../phase1-service/network.mjs';
import { createPhase2PonderClient } from './ponder-client.mjs';
import {FEE_ADAPTER_TYPES} from '../phase2-fees/sdk.mjs';
import {loadFeeComponents} from '../phase2-fees/artifacts.mjs';
import {normalizeServiceFeePolicy} from '../phase2-fees/policy.mjs';
import {createPublisherStatusLoader,publicMirrorURL,fetchPublicJSON} from './publisher-status.mjs';
import {createSubmissionControlLoader} from './submission-control.mjs';
import {acceptedAssociationPolicy} from './association-policy.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=value=>createHash('sha256').update(value).digest('hex');
async function read(file,{privateFile=false,maxBytes=8*1024*1024}={}){
  const filename=path.resolve(file),handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await handle.stat();check(stat.isFile()&&stat.size<=maxBytes,'INVALID_RUNTIME_FILE');check(await fs.realpath(filename)===filename,'SYMLINK_RUNTIME_FILE');if(privateFile)check((stat.mode&0o077)===0,'PRIVATE_FILE_PERMISSIONS');return await handle.readFile();}finally{await handle.close();}
}
/** Fixed local confirmed publications only; old documents require a still-live
 * canonical acceptedPolicy. Candidate association-set-* files are never loaded. */
export function createAssociationSetFileLoader(filename,{onUnavailable,mirrorURL,fetchImpl=globalThis.fetch}={}){
  check(typeof filename==='string'&&filename.length>0,'INVALID_ASSOCIATION_SET_FILE');
  check(onUnavailable===undefined||typeof onUnavailable==='function','INVALID_ASSOCIATION_SET_DIAGNOSTIC');
  check(mirrorURL===undefined||publicMirrorURL(mirrorURL)&&typeof fetchImpl==='function','INVALID_ASSOCIATION_SET_MIRROR');
  let diagnostic={available:false,code:'ASSOCIATION_SET_NOT_LOADED'};
  const unavailable=code=>{diagnostic={available:false,code};try{onUnavailable?.(code);}catch{}return null;};
  let previous=null;
  const authenticate=(set,policy)=>{
    if(!set||Object.getPrototypeOf(set)!==Object.prototype||!Array.isArray(set.leaves)||set.leaves.length>2**20)return unavailable('ASSOCIATION_SET_INVALID');
    let digest,root;try{digest=associationSetDigest(set.leaves);root=String(phase2Tree(set.leaves).root);}catch{return unavailable('ASSOCIATION_SET_INVALID');}
    const document={...set,root,digest,leaves:set.leaves.map(String)};
    // Preserve the legacy latest-only DTO. State independently gates expiry,
    // revocation and provider identity even when latest leaves remain readable.
    if(digest.toLowerCase()===policy.cidDigest?.toLowerCase()&&root===String(policy.root)){
      previous=document;diagnostic={available:true,code:null};return {leaves:document.leaves};
    }
    const accepted=acceptedAssociationPolicy(policy,document,policy.blockTimestamp);
    if(!accepted)return unavailable('ASSOCIATION_SET_POLICY_MISMATCH');
    previous=document;diagnostic={available:true,code:null};return {leaves:document.leaves,policy:accepted};
  };
  const loader=async policy=>{
    const directory=path.dirname(path.resolve(filename));
    let current;try{current=JSON.parse(await read(filename,{maxBytes:80*1024*1024}));}catch{}
    let acceptedFallback=null;
    if(current){const result=authenticate(current,policy);if(result&&!result.policy)return result;if(result)acceptedFallback=result;}
    // Prefer an independently confirmed latest archive if publication completed
    // its archive write before current.json's atomic replacement was visible.
    if(typeof policy.cidDigest==='string'&&/^0x[0-9a-f]{64}$/i.test(policy.cidDigest))try{
      const set=JSON.parse(await read(path.join(directory,`confirmed-association-set-${policy.cidDigest.slice(2).toLowerCase()}.json`),{maxBytes:80*1024*1024}));
      const result=authenticate(set,policy);if(result&&!result.policy)return result;
    }catch{}
    if(acceptedFallback){diagnostic={available:true,code:null};return acceptedFallback;}
    // Recover a publication retained in this process during an atomic rename or
    // legacy deletion. It still needs current-chain acceptance on EVERY call.
    if(previous){const result=authenticate(previous,policy);if(result)return result;}
    const digests=[policy.cidDigest,...(policy.acceptedPolicies??[]).slice(0,16).map(entry=>entry.cidDigest)]
      .filter(value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value));
    for(const digest of new Set(digests)){
      try{
        const set=JSON.parse(await read(path.join(directory,`confirmed-association-set-${digest.slice(2).toLowerCase()}.json`),{maxBytes:80*1024*1024}));
        const result=authenticate(set,policy);if(result)return result;
      }catch{}
    }
    // Upgrade recovery: old publishers wrote publisher-status before deleting
    // current.json during an awaiting-confirmations tick. Only its confirmed
    // active document is eligible; never its pending associationSet proposal.
    try{
      const status=JSON.parse(await read(path.join(directory,'publisher-status.json'),{maxBytes:80*1024*1024}));
      const set=status.activeAssociationSet,confirmed=status.activePolicy??status.currentPolicy;
      if(status.schema==='phase2-asp-operator-result/v1'&&set&&confirmed
        &&set.root===confirmed.root&&set.digest?.toLowerCase()===confirmed.cidDigest?.toLowerCase()){
        const result=authenticate(set,policy);if(result)return result;
      }
    }catch{}
    // Public mirror, keyed by the on-chain digest. Its bytes are untrusted:
    // the same recomputation of digest and root gates every mirrored document,
    // so a wrong or tampered object is simply unavailable, never accepted.
    if(mirrorURL!==undefined)for(const digest of new Set(digests)){
      try{
        const set=await fetchPublicJSON(fetchImpl,mirrorURL+'association-sets/'+digest.toLowerCase()+'.json',80*1024*1024);
        const result=authenticate(set,policy);if(result){diagnostic={...diagnostic,source:'mirror'};return result;}
      }catch{}
    }
    return unavailable('ASSOCIATION_SET_NO_ACCEPTED_CONFIRMED_DOCUMENT');
  };
  // Diagnostic codes contain no path or file contents and cannot grant approval.
  loader.status=()=>({...diagnostic});return loader;
}

export async function startPhase2ASPRuntime(env=process.env,overrides={}){
  const profile=JSON.parse(await read(env.PHASE2_ASP_PROFILE_PATH??path.join(ROOT,'config/phase2-asp-local.json')));
  normalizeProfile(profile);
  const serviceFeePolicy=env.PHASE2_ASP_SERVICE_FEES_FILE?normalizeServiceFeePolicy(JSON.parse(await read(env.PHASE2_ASP_SERVICE_FEES_FILE))):null;
  const artifactBytes=await read(env.PHASE2_ASP_ARTIFACTS_PATH??path.join(ROOT,'artifacts/phase2-asp/contracts.json'));
  const artifacts=JSON.parse(artifactBytes),meta=artifacts._meta;
  check(profile.artifactSHA256===sha(artifactBytes),'ARTIFACT_PROFILE_MISMATCH');
  check(meta.experimental===true&&meta.testOnly===true&&meta.productionReady===false&&meta.allowedChainIds.includes(profile.chain.id),'TEST_ARTIFACT_REQUIRED');
  check(meta.model?.ASP===true&&meta.model.associationPolicy==='current-note'&&meta.model.publicHolderExit===true&&meta.model.exitRequiresASP===false&&meta.model.upgradeable===false,'CURRENT_NOTE_ASP_ARTIFACT_REQUIRED');
  const rpcUrl=env.PHASE2_ASP_RPC_URL??profile.chain.rpcUrl,url=new URL(rpcUrl);
  check(!url.username&&!url.password&&!url.search&&!url.hash&&(url.protocol==='https:'||url.protocol==='http:'&&['127.0.0.1','localhost','host.docker.internal'].includes(url.hostname)),'RPC_URL_REJECTED');
  if(profile.chain.id===46630)check(['rpc.testnet.chain.robinhood.com','robinhood-sepolia-rpc.publicnode.com'].includes(url.hostname)&&url.protocol==='https:','PUBLIC_TESTNET_RPC_REJECTED');
  const rpcClient=overrides.client??createPublicClient({transport:http(rpcUrl,{timeout:20000,retryCount:0}),cacheTime:0});
  check(env.PHASE2_ASP_PONDER_FALLBACK===undefined||['rpc','reject'].includes(env.PHASE2_ASP_PONDER_FALLBACK),'INVALID_PONDER_FALLBACK');
  check(env.PHASE2_ASP_PONDER_MODE===undefined||['full','logs'].includes(env.PHASE2_ASP_PONDER_MODE),'INVALID_PONDER_MODE');
  const client=env.PHASE2_ASP_PONDER_URL?createPhase2PonderClient({client:rpcClient,profile,baseURL:env.PHASE2_ASP_PONDER_URL,
    fallbackToRpc:env.PHASE2_ASP_PONDER_FALLBACK!=='reject',mode:env.PHASE2_ASP_PONDER_MODE??'full'}):rpcClient;
  check(env.PHASE2_ASP_MIN_PUBLISH_INTERVAL_SECONDS===undefined||/^[1-9][0-9]{0,6}$/.test(env.PHASE2_ASP_MIN_PUBLISH_INTERVAL_SECONDS),'INVALID_ASP_MIN_PUBLISH_INTERVAL');
  const publisherStatusLoader=overrides.publisherStatusLoader??createPublisherStatusLoader({client,profile,
    filename:env.PHASE2_ASP_PUBLISHER_STATUS_FILE,mirrorURL:env.PHASE2_ASP_PUBLISHER_STATUS_MIRROR_URL,
    minPublishIntervalSeconds:env.PHASE2_ASP_MIN_PUBLISH_INTERVAL_SECONDS===undefined?null:Number(env.PHASE2_ASP_MIN_PUBLISH_INTERVAL_SECONDS)});
  check(env.PHASE2_ASP_SIGNING_ENABLED===undefined||['0','1'].includes(env.PHASE2_ASP_SIGNING_ENABLED),'INVALID_SIGNING_FLAG');
  let signer=null,authorizeFee=overrides.authorizeFee,settleFee=overrides.settleFee;
  if(env.PHASE2_ASP_SIGNING_ENABLED==='1'){
    check(/^[1-9][0-9]{0,17}$/.test(env.PHASE2_ASP_GAS_BUDGET_WEI??''),'EXPLICIT_GAS_BUDGET_REQUIRED');
    check(BigInt(env.PHASE2_ASP_GAS_BUDGET_WEI)<=(profile.chain.id===31341?100000000000000000n:500000000000000n),'TEST_GAS_BUDGET_EXCEEDED');
    if(profile.chain.id===46630&&(!authorizeFee||!settleFee)){
      check(env.PHASE2_ASP_SHARED_BUDGET==='1'&&env.PHASE2_ASP_BUDGET_DIR,'PUBLIC_RELAY_SHARED_BUDGET_REQUIRED');
      const{createASPBudgetGuard}=await import('./budget.mjs');
      ({authorizeFee,settleFee}=await createASPBudgetGuard({client,profile,directory:env.PHASE2_ASP_BUDGET_DIR,rootDirectory:env.PHASE2_ASP_BUDGET_ROOT??ROOT}));
    }
    if(overrides.signer)signer=overrides.signer;
    else{
      check(env.PHASE2_ASP_KEYSTORE_FILE&&env.PHASE2_ASP_PASSWORD_FILE,'EXPLICIT_KEYSTORE_REQUIRED');
      const password=(await read(env.PHASE2_ASP_PASSWORD_FILE,{privateFile:true,maxBytes:1024})).toString('utf8').trimEnd();
      const keystore=await read(env.PHASE2_ASP_KEYSTORE_FILE,{privateFile:true,maxBytes:1024*1024});
      try{const wallet=await Wallet.fromEncryptedJson(keystore.toString('utf8'),password);signer=privateKeyToAccount(wallet.privateKey);}catch{throw new Error('KEYSTORE_DECRYPTION_FAILED');}
    }
    check(profile.relayer&&signer.address.toLowerCase()===profile.relayer.toLowerCase(),'RELAYER_ADDRESS_MISMATCH');
  }
  const routes=env.PHASE2_ASP_ROUTES_FILE?JSON.parse(await read(env.PHASE2_ASP_ROUTES_FILE)):[];
  let routeArtifacts;if(routes.length){const bytes=await read(env.PHASE2_ASP_ROUTE_ARTIFACTS_PATH??path.join(ROOT,'artifacts/phase2-routes/contracts.json'));routeArtifacts=JSON.parse(bytes);check(routeArtifacts._meta?.testOnly===true&&routeArtifacts._meta.productionReady===false,'TEST_ROUTE_ARTIFACT_REQUIRED');}
  if(routes.some(entry=>entry.route?.adapterType==='Phase2Router02Adapter')){const bytes=await read(env.PHASE2_ASP_ROUTER02_ARTIFACTS_PATH??path.join(ROOT,'artifacts/phase2-router02/contracts.json')),router02=JSON.parse(bytes);check(router02._meta?.testOnly===true&&router02._meta.productionReady===false&&router02._meta.adapterType==='Phase2Router02Adapter','TEST_ROUTER02_ARTIFACT_REQUIRED');routeArtifacts={...routeArtifacts,Phase2Router02Adapter:router02.Phase2Router02Adapter};}
  const paidRoutes=routes.filter(entry=>FEE_ADAPTER_TYPES.includes(entry.route?.adapterType));
  if(paidRoutes.length){const components=await loadFeeComponents({filename:env.PHASE2_ASP_FEE_ARTIFACTS_PATH??path.join(ROOT,'artifacts/phase2-fees/contracts.json'),rootDirectory:ROOT,routes:paidRoutes,chainId:profile.chain.id});routeArtifacts={...routeArtifacts,...components.contracts};}
  const port=Number(env.PHASE2_ASP_PORT??8794),host=env.PHASE2_ASP_HOST??'127.0.0.1';
  check(Number.isSafeInteger(port)&&port>=0&&port<=65535&&['127.0.0.1','0.0.0.0','::1'].includes(host),'INVALID_LISTEN_OPTIONS');
  const networkPolicy=createNetworkPolicy({PHASE1_ALLOWED_HOSTS:env.PHASE2_ASP_ALLOWED_HOSTS,PHASE1_ALLOWED_ORIGINS:env.PHASE2_ASP_ALLOWED_ORIGINS});
  const quoteRoute=overrides.quoteRoute??(async options=>{const{quotePhase2Route}=await import('./quote.mjs');return quotePhase2Route(options);});
  return createPhase2ASPService({client,profile,artifacts,signer,authorizeFee,settleFee,routes,routeArtifacts,quoteRoute,serviceFeePolicy,publisherStatusLoader,submissionControlLoader:overrides.submissionControlLoader??(env.PHASE2_ASP_SUBMISSION_CONTROL_FILE?createSubmissionControlLoader(env.PHASE2_ASP_SUBMISSION_CONTROL_FILE):undefined),
    associationSetFile:env.PHASE2_ASP_ASSOCIATION_SET_FILE,
    associationSetLoader:env.PHASE2_ASP_ASSOCIATION_SET_FILE?createAssociationSetFileLoader(env.PHASE2_ASP_ASSOCIATION_SET_FILE,{mirrorURL:env.PHASE2_ASP_ASSOCIATION_SET_MIRROR_URL}):undefined,
    directory:env.PHASE2_ASP_STATE_DIR??path.join(ROOT,'artifacts/phase2-asp/runtime'),gasBudgetWei:BigInt(env.PHASE2_ASP_GAS_BUDGET_WEI??'100000000000000'),port,host,networkPolicy});
}
export const startPhase2Runtime=startPhase2ASPRuntime;
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const server=await startPhase2ASPRuntime();console.log(JSON.stringify({service:'phase2-asp',port:server.port,testOnly:true,productionReady:false}));let stopping=false;
    for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{if(stopping)return;stopping=true;try{await server.close();process.exit(0);}catch{process.exit(1);}});
  }catch(error){console.error(/^[A-Z][A-Z0-9_]{1,70}$/.test(error.code??error.message)?error.code??error.message:'PHASE2_ASP_STARTUP_FAILED');process.exit(1);}
}
