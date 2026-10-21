// SPDX-License-Identifier: Apache-2.0
// Optional current-note ASP relay. Public exits do not depend on ASP availability.
import {createBoundedHttpServer,normalizeHttpLimits,serviceJson} from './http.mjs';
import {confirmedMissingContractFunction,relayStage,relayJobRecovery,relayErrorReply,validRelayJobId} from './relay-errors.mjs';
import {DEFAULT_PUBLISHER_STATUS} from './publisher-status.mjs';
import {createASPPublicationEvents} from '../phase2-mainnet/asp-event-source.mjs';
import { createHash } from 'node:crypto';
import { decodeFunctionData, encodeFunctionData, keccak256, parseTransaction, recoverTransactionAddress } from 'viem';
import { openServiceStore } from '../phase1-service/store.mjs';
import { createNetworkPolicy } from '../phase1-service/network.mjs';
import { createPhase2Indexer, phase2Identity } from './state.mjs';
import { normalizeProfile, normalizeSwapRoute, normalizeSwapAction, swapActionEnvelope, joinSplitContext, holderExitContext, FIELD, PRODUCTION_PROFILE_SCHEMA } from './sdk.mjs';
import {FEE_ADAPTER_TYPES,normalizeFeeSwapRoute,normalizeFeeSwapAction,feeSwapActionEnvelope} from '../phase2-fees/sdk.mjs';
import {normalizeServiceFeePolicy,quoteServiceFee,validateCommercialFee} from '../phase2-fees/policy.mjs';
import {createQuoteGate,quotePhase2Aggregate} from '../phase2-aggregator/quotes.mjs';

const MAX128=(1n<<128n)-1n, BASE_FIELD=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const ZERO='0x'+'00'.repeat(20), MAX_JOBS=256;
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const wire=value=>JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?String(v):v));
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const isHash=value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value);
function exact(value,keys){check(value&&Object.getPrototypeOf(value)===Object.prototype,'INVALID_OBJECT');const own=Reflect.ownKeys(value);check(own.length===keys.length&&own.every(k=>typeof k==='string'&&keys.includes(k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')),'UNEXPECTED_FIELDS');}
function integer(value,max=(1n<<256n)-1n){check(typeof value==='string'&&value.length<=78&&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<=max,'INVALID_INTEGER');return BigInt(value);}
function address(value){check(typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value),'INVALID_ADDRESS');return value.toLowerCase();}
function array(value,length,fn){check(Array.isArray(value)&&value.length===length&&Reflect.ownKeys(value).length===length+1&&Array.from({length},(_,i)=>Object.hasOwn(Object.getOwnPropertyDescriptor(value,String(i))??{},'value')).every(Boolean),'INVALID_ARRAY');return value.map(fn);}
function proof(t,count){return {pA:array(t.pA,2,x=>integer(x,BASE_FIELD-1n)),pB:array(t.pB,2,row=>array(row,2,x=>integer(x,BASE_FIELD-1n))),pC:array(t.pC,2,x=>integer(x,BASE_FIELD-1n)),pubSignals:array(t.pubSignals,count,x=>integer(x,FIELD-1n))};}
function cipher(value){check(typeof value==='string'&&/^0x[0-9a-f]{512}$/i.test(value),'INVALID_CIPHERTEXT');return value.toLowerCase();}
function adapterContract(entry,artifacts){const type=entry?.route?.adapterType??'Phase2RouteAdapter';check(['Phase2RouteAdapter','Phase2Router02Adapter',...FEE_ADAPTER_TYPES].includes(type)&&Array.isArray(artifacts?.[type]?.abi),'UNSUPPORTED_ROUTE_ADAPTER');return artifacts[type];}
function routesFor(profile,routes=[]){
  check(Array.isArray(routes)&&routes.length<=16,'INVALID_ROUTES');const ids=new Set();
  return routes.map(entry=>{exact(entry,['id','route','targetProfile']);check(typeof entry.id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(entry.id)&&!ids.has(entry.id),'INVALID_ROUTE_ID');ids.add(entry.id);
    check(entry.route?.executionEnabled===undefined||entry.route.executionEnabled===true,'ROUTE_EXECUTION_DISABLED');check(['Phase2RouteAdapter','Phase2Router02Adapter',...FEE_ADAPTER_TYPES].includes(entry.route?.adapterType??'Phase2RouteAdapter'),'UNSUPPORTED_ROUTE_ADAPTER');const paid=FEE_ADAPTER_TYPES.includes(entry.route?.adapterType),geometry=(paid?normalizeFeeSwapRoute:normalizeSwapRoute)({sourceProfile:profile,targetProfile:entry.targetProfile,route:entry.route});check(!['Phase2Router02Adapter','Phase2FeeRouter02Adapter'].includes(entry.route?.adapterType)||geometry.protocol===0,'ROUTER02_REQUIRES_UNISWAP_V3');phase2Identity(entry.targetProfile);
    check(profile.genesisHash===entry.targetProfile.genesisHash&&profile.artifactSHA256===entry.targetProfile.artifactSHA256,'ROUTE_PROFILE_MISMATCH');
    check(isHash(entry.route.runtimeCodeHashes?.adapter),'PINNED_ADAPTER_REQUIRED');return {...entry,geometry};});
}
/** Only executable fee adapters can satisfy an enabled relayer fee policy.
 * Keep the complete configured registry for recovery of older signed jobs.
 */
export function serviceRoutesForFeePolicy(routes,policy){
  return policy===null?routes:routes.filter(entry=>FEE_ADAPTER_TYPES.includes(entry.route.adapterType)&&entry.route.feeBps===policy.serviceFeeBps);
}

/** Canonical public proof requests only. No deposits, approval calls, private notes or arbitrary calldata. */
export function validateRelayRequest(body,{profile,artifacts,processor,routes=[],routeArtifacts,feeRecipients}){
  normalizeProfile(profile);check(body&&Object.getPrototypeOf(body)===Object.prototype&&Object.hasOwn(Object.getOwnPropertyDescriptor(body,'kind')??{},'value'),'INVALID_JOB_KIND');check(['transact','holderExit','ragequit','swap'].includes(body.kind),'INVALID_JOB_KIND');
  const hasFeeQuote=Object.hasOwn(body,'feeQuoteId');
  exact(body,[...(body.kind==='swap'?['id','kind','routeId','transaction']:['id','kind','transaction']),...(hasFeeQuote?['feeQuoteId']:[])]);
  if(hasFeeQuote)check(typeof body.feeQuoteId==='string'&&/^[0-9a-f]{64}$/.test(body.feeQuoteId),'INVALID_FEE_QUOTE_ID');
  check(typeof body.id==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(body.id),'INVALID_ID');const processorAddress=address(processor),t=body.transaction;
  // Where a relay fee may be paid: the processor itself unless the operator also names its treasury.
  const payees=new Set((feeRecipients??[processor]).map(address));
  let args,data,to=address(profile.pool.address),nullifiers,signals,extData,encryptedOutputs,routeEntry=null;
  if(body.kind==='holderExit'||body.kind==='ragequit'){
    exact(t,['pA','pB','pC','pubSignals','data']);const p=proof(t,5);signals=p.pubSignals;
    exact(t.data,['processor','recipient','feeRecipient','fee']);const d=t.data;
    extData={processor:address(d.processor),recipient:address(d.recipient),feeRecipient:address(d.feeRecipient),fee:integer(d.fee,MAX128)};
    check(extData.processor===processorAddress&&extData.recipient!==ZERO&&extData.recipient!==to,'INVALID_EXIT_PROCESSOR_OR_RECIPIENT');
    check(signals[0]>0n&&signals[1]>0n&&signals[2]>0n&&signals[2]<=MAX128&&signals[3]===BigInt(profile.pool.scope),'INVALID_EXIT_SIGNALS');
    check(extData.fee<=signals[2]&&(extData.fee===0n||payees.has(extData.feeRecipient)),'INVALID_RELAY_FEE');
    check(body.kind!=='ragequit'||extData.fee===0n&&extData.feeRecipient===ZERO,'INVALID_RAGEQUIT_FEE');
    check(signals[4]===holderExitContext(profile,extData),'EXIT_CONTEXT_MISMATCH');args=[extData,p];nullifiers=[String(signals[1])];
    data=encodeFunctionData({abi:artifacts.Phase2ASPPool.abi,functionName:body.kind,args});
  }else{
    exact(t,['pA','pB','pC','pubSignals','extData','encryptedOutputs',...(body.kind==='swap'?['action']:[])]);const p=proof(t,9);signals=p.pubSignals;
    exact(t.extData,['recipient','feeRecipient','processor','publicIn','publicOut','fee']);const e=t.extData;
    extData={recipient:address(e.recipient),feeRecipient:address(e.feeRecipient),processor:address(e.processor),publicIn:integer(e.publicIn,MAX128),publicOut:integer(e.publicOut,MAX128),fee:integer(e.fee,MAX128)};
    check(extData.publicIn===0n&&signals[1]===0n&&signals[2]===extData.publicOut&&signals[4]===BigInt(profile.pool.scope),'PUBLIC_SIGNAL_MISMATCH');
    check(signals[5]>0n&&signals[6]>0n&&signals[5]!==signals[6],'INVALID_NULLIFIERS');
    check(extData.fee<=extData.publicOut&&(extData.fee===0n||payees.has(extData.feeRecipient)),'INVALID_RELAY_FEE');
    encryptedOutputs=array(t.encryptedOutputs,2,cipher);nullifiers=signals.slice(5,7).map(String);
    if(body.kind==='transact'){
      check(extData.processor===processorAddress,'RELAY_PROCESSOR_MISMATCH');
      check(extData.publicOut===0n||extData.recipient!==ZERO&&extData.recipient!==to,'INVALID_PUBLIC_RECIPIENT');
      args=[p.pA,p.pB,p.pC,p.pubSignals,extData,encryptedOutputs];data=encodeFunctionData({abi:artifacts.Phase2ASPPool.abi,functionName:'transact',args});
    }else{
      routeEntry=routesFor(profile,routes).find(r=>r.id===body.routeId);check(routeEntry,'UNKNOWN_ROUTE');const adapter=adapterContract(routeEntry,routeArtifacts);
      const paid=FEE_ADAPTER_TYPES.includes(routeEntry.route.adapterType);
      exact(t.action,['processor','amountIn','minAmountOut','deadline','targetPrecommitment','encryptedTemplate',...(paid?['maxServiceFee']:[])]);
      // Validate descriptors and canonical decimal strings before passing to SDK helpers.
      const rawAction={processor:address(t.action.processor),amountIn:integer(t.action.amountIn,MAX128),minAmountOut:integer(t.action.minAmountOut,MAX128),deadline:integer(t.action.deadline),targetPrecommitment:integer(t.action.targetPrecommitment,FIELD-1n),encryptedTemplate:cipher(t.action.encryptedTemplate),...(paid?{maxServiceFee:integer(t.action.maxServiceFee,MAX128)}:{})};
      const action=(paid?normalizeFeeSwapAction:normalizeSwapAction)(rawAction);to=routeEntry.geometry.adapter;
      check(action.processor===processorAddress&&extData.processor===to&&extData.recipient===to&&extData.feeRecipient===ZERO&&extData.fee===0n&&extData.publicOut===action.amountIn&&signals[8]===0n,'SWAP_AUTHORIZATION_MISMATCH');
      check(encryptedOutputs[1]===(paid?feeSwapActionEnvelope:swapActionEnvelope)({sourceProfile:profile,targetProfile:routeEntry.targetProfile,route:routeEntry.route,action}),'SWAP_ACTION_MISMATCH');
      args=[action,p,extData,encryptedOutputs];data=encodeFunctionData({abi:adapter.abi,functionName:'swap',args});
    }
  }
  return {id:body.id,kind:body.kind,routeId:body.routeId??null,...(hasFeeQuote?{feeQuoteId:body.feeQuoteId}:{}),to,data,nullifiers,signals,extData,encryptedOutputs,routeEntry,args,
    fingerprint:digest({data,to,chainId:profile.chain.id})};
}
function requestFromStored(job,{artifacts,routeArtifacts,routes}){
  const swap=job.kind==='swap',entry=swap?routes.find(r=>r.id===job.routeId):null;if(swap)check(entry,'UNKNOWN_ROUTE');const decoded=decodeFunctionData({abi:swap?adapterContract(entry,routeArtifacts).abi:artifacts.Phase2ASPPool.abi,data:job.data});
  check(decoded.functionName===job.kind,'INVALID_STORED_CALL');let transaction;
  if(swap){const [action,p,extData,encryptedOutputs]=decoded.args;transaction={action,...p,extData,encryptedOutputs};}
  else if(job.kind==='transact'){const [pA,pB,pC,pubSignals,extData,encryptedOutputs]=decoded.args;transaction={pA,pB,pC,pubSignals,extData,encryptedOutputs};}
  else{const [data,p]=decoded.args;transaction={...p,data};}
  return wire({id:job.id,kind:job.kind,...(swap?{routeId:job.routeId}:{}),transaction});
}

/** Checksums detect torn writes; this additionally verifies transaction semantics and signatures. */
export async function validateRelayStore(state,{profile,artifacts,identity,processor,maxGas,gasBudgetWei,routes=[],routeArtifacts}){
  exact(state,['schema','identity','processor','jobs']);check(state.schema==='phase2-asp-relay-jobs/v1'&&state.identity===identity&&Array.isArray(state.jobs)&&state.jobs.length<=MAX_JOBS,'INVALID_RELAY_STORE');
  check(state.processor===null?state.jobs.length===0:address(state.processor)===state.processor,'INVALID_STORE_PROCESSOR');if(processor)check(state.processor===null||state.processor===address(processor),'STORE_PROCESSOR_MISMATCH');
  const ids=new Set(),nonces=new Set(),hashes=new Set(),nfs=new Set();let reserved=0n;
  for(const job of state.jobs){const signed=job?.status!=='preparing',settled=['confirmed','reverted'].includes(job?.status);
    exact(job,['id','kind','routeId','fingerprint','nullifiers','status','nonce','feeCeilingWei','data','to','chainId','gas','gasPrice',...(signed?['raw','hash']:[]),...(settled?['blockHash','blockNumber','feeWei']:[])]);
    check(['preparing','signed','pending','confirmed','reverted'].includes(job.status)&&Number.isSafeInteger(job.nonce)&&job.nonce>=0&&!nonces.has(job.nonce)&&!ids.has(job.id),'DUPLICATE_OR_INVALID_JOB');ids.add(job.id);nonces.add(job.nonce);
    check(job.chainId===profile.chain.id&&typeof job.data==='string'&&/^0x[0-9a-f]+$/.test(job.data)&&job.data.length<=32768,'INVALID_STORED_INTENT');
    check(job.kind==='swap'?typeof job.routeId==='string':job.routeId===null,'INVALID_STORED_ROUTE');
    const intent=validateRelayRequest(requestFromStored(job,{artifacts,routeArtifacts,routes}),{profile,artifacts,processor:state.processor,routes,routeArtifacts});
    check(intent.to===job.to&&intent.data===job.data&&intent.fingerprint===job.fingerprint&&JSON.stringify(intent.nullifiers)===JSON.stringify(job.nullifiers),'STORED_INTENT_MISMATCH');
    for(const nf of intent.nullifiers)if(job.status!=='reverted'){check(!nfs.has(nf),'DUPLICATE_STORED_NULLIFIER');nfs.add(nf);}
    const gas=integer(job.gas),gasPrice=integer(job.gasPrice),ceiling=integer(job.feeCeilingWei);check(gas>0n&&gas<=maxGas&&gasPrice>0n&&ceiling===gas*gasPrice,'INVALID_STORED_FEE_CEILING');
    if(signed){check(typeof job.raw==='string'&&job.raw.length<=32768&&/^0x[0-9a-f]+$/.test(job.raw)&&isHash(job.hash)&&keccak256(job.raw)===job.hash&&!hashes.has(job.hash),'STORED_RAW_HASH_MISMATCH');hashes.add(job.hash);
      const tx=parseTransaction(job.raw),sender=await recoverTransactionAddress({serializedTransaction:job.raw});
      check(tx.type==='legacy'&&tx.chainId===job.chainId&&tx.to?.toLowerCase()===job.to&&tx.data===job.data&&(tx.value??0n)===0n&&(tx.nonce??0)===job.nonce&&tx.gas===gas&&tx.gasPrice===gasPrice&&sender.toLowerCase()===state.processor,'STORED_SIGNATURE_INTENT_MISMATCH');}
    if(settled){check(isHash(job.blockHash),'INVALID_STORED_RECEIPT');integer(job.blockNumber);const cost=integer(job.feeWei);check(cost<=ceiling,'STORED_COST_EXCEEDS_CEILING');reserved+=cost;}else reserved+=ceiling;
  }
  check(reserved<=gasBudgetWei,'STORED_GAS_BUDGET_EXCEEDED');return state;
}
export async function verifyRelayReceipt(job,{client,processor}){
  let receipt;try{receipt=await client.getTransactionReceipt({hash:job.hash});}catch(error){if(error.name==='TransactionReceiptNotFoundError'&&['signed','pending'].includes(job.status))return null;throw Object.assign(new Error('KNOWN_RECEIPT_MISSING_OR_UNREADABLE'),{code:'KNOWN_RECEIPT_MISSING_OR_UNREADABLE'});}
  check(receipt.transactionHash===job.hash&&receipt.from?.toLowerCase()===processor.toLowerCase()&&receipt.to?.toLowerCase()===job.to&&['success','reverted'].includes(receipt.status)&&typeof receipt.blockNumber==='bigint'&&receipt.blockNumber>=0n&&isHash(receipt.blockHash),'RELAY_RECEIPT_IDENTITY_MISMATCH');
  check(typeof receipt.gasUsed==='bigint'&&receipt.gasUsed>=0n&&receipt.gasUsed<=BigInt(job.gas)&&typeof receipt.effectiveGasPrice==='bigint'&&receipt.effectiveGasPrice>0n&&receipt.effectiveGasPrice<=BigInt(job.gasPrice),'RELAY_RECEIPT_FEE_MISMATCH');
  check((await client.getBlock({blockNumber:receipt.blockNumber})).hash===receipt.blockHash,'RELAY_RECEIPT_REORGANIZED');const cost=receipt.gasUsed*receipt.effectiveGasPrice;check(cost<=BigInt(job.feeCeilingWei),'RELAY_COST_EXCEEDS_CEILING');
  if(['confirmed','reverted'].includes(job.status))check(job.blockHash===receipt.blockHash&&BigInt(job.blockNumber)===receipt.blockNumber&&BigInt(job.feeWei)===cost&&job.status===(receipt.status==='success'?'confirmed':'reverted'),'STORED_RECEIPT_MISMATCH');return receipt;
}
// A superseded or expiring policy must stay accepted this long past the snapshot,
// so a relayed transaction does not revert while it waits for inclusion.
export const RELAY_POLICY_MARGIN_SECONDS=120n;

/** routeAdapters: known route adapter addresses (lowercase); see assertRagequitRecipient.
 * Normal spends may bind any policy the registry accepts at the snapshot block
 * (audit M2), not only the latest one.
 */
export function validateIntentState(intent,snapshot,{profile,routeAdapters=new Set()}){
  check(!intent.nullifiers.some(nf=>snapshot.nullifiers.includes(nf)),'NULLIFIER_SPENT');
  if(['holderExit','ragequit'].includes(intent.kind)){
    check(snapshot.commitments.includes(String(intent.signals[0])),'EXIT_COMMITMENT_NOT_FOUND');
    if(intent.kind==='ragequit'){check(!routeAdapters.has(intent.extData.recipient),'RAGEQUIT_TO_ROUTE_ADAPTER');const deposit=snapshot.deposits.find(d=>d.commitment===String(intent.signals[0]));check(deposit&&deposit.originalDepositor.toLowerCase()===intent.extData.recipient&&BigInt(deposit.value)===intent.signals[2],'RAGEQUIT_ORIGINAL_DEPOSIT_MISMATCH');}return;
  }
  // Older snapshots carry only the latest policy.
  const accepted=Array.isArray(snapshot.asp?.acceptedPolicies)?snapshot.asp.acceptedPolicies:snapshot.asp?.expired===false?[snapshot.asp]:[];
  check(snapshot.asp&&accepted.length>0&&Array.isArray(snapshot.asp.leaves),'ASP_POLICY_UNAVAILABLE');
  const policy=accepted.find(candidate=>intent.signals[3]===joinSplitContext(profile,intent.extData,intent.encryptedOutputs,candidate));
  check(policy,'STALE_ASP_PROOF');
  check(policy.acceptedUntil===undefined||BigInt(policy.acceptedUntil)>BigInt(snapshot.blockTimestamp)+RELAY_POLICY_MARGIN_SECONDS,'ASP_POLICY_ENDING');
  if(intent.kind==='swap')check(intent.args[0].deadline>=BigInt(snapshot.blockTimestamp),'EXPIRED_SWAP');
}
const TARGET_POOL_ABI=[{type:'function',name:'TARGET_POOL',stateMutability:'view',inputs:[],outputs:[{type:'address'}]}];
/** Audit L1: a swap's target note records the route adapter as original depositor,
 * and ragequit can only pay that adapter, which cannot forward the refund. Any
 * contract whose TARGET_POOL() is this pool is treated as an adapter, so inbound,
 * outbound, historical and unconfigured adapters are all covered. Such notes
 * leave through holderExit. Contract depositors keep their on-chain ragequit.
 */
export async function assertRagequitRecipient(client,intent,{profile,routeAdapters=new Set(),blockNumber}){
  if(intent.kind!=='ragequit')return;
  const recipient=intent.extData.recipient.toLowerCase();
  check(!routeAdapters.has(recipient),'RAGEQUIT_TO_ROUTE_ADAPTER');
  const code=await client.getCode({address:recipient,blockNumber});
  if(!code||code==='0x')return;
  let target;
  // A contract without TARGET_POOL() reverts or returns no data: not an adapter.
  // Anything else, including RPC failures wrapped by viem, refuses the job.
  try{target=await client.readContract({address:recipient,abi:TARGET_POOL_ABI,functionName:'TARGET_POOL',blockNumber});}
  catch(error){if(confirmedMissingContractFunction(error))return;throw error;}
  check(typeof target!=='string'||target.toLowerCase()!==profile.pool.address.toLowerCase(),'RAGEQUIT_TO_ROUTE_ADAPTER');
}
async function verifyRouteLive(client,entry,routeArtifacts){
  const {route,targetProfile,geometry:r}=entry,head=await client.getBlockNumber(),block=await client.getBlock({blockNumber:head});
  for(const pin of [targetProfile.pool,targetProfile.verifier,targetProfile.exitVerifier,targetProfile.registry])check(keccak256(await client.getCode({address:pin.address,blockNumber:head})??'0x')===pin.runtimeCodeHash,'ROUTE_TARGET_RUNTIME_MISMATCH');
  for(const role of ['adapter','router','factory','wrappedNative']){check(isHash(route.runtimeCodeHashes?.[role]),'ROUTE_RUNTIME_PIN_REQUIRED');check(keccak256(await client.getCode({address:r[role],blockNumber:head})??'0x')===route.runtimeCodeHashes[role],'ROUTE_RUNTIME_MISMATCH');}
  const expected={SOURCE_POOL:r.sourcePool,TARGET_POOL:r.targetPool,ROUTER:r.router,WRAPPED_NATIVE:r.wrappedNative,FACTORY:r.factory,SOURCE_ASSET:r.sourceAsset,TARGET_ASSET:r.targetAsset,PROTOCOL:r.protocol,HOPS:r.hops,PATH_HASH:r.pathHash,PATH:r.path};
  if(FEE_ADAPTER_TYPES.includes(route.adapterType)){expected.FEE_BPS=r.feeBps;expected.TREASURY=r.treasury;}
  for(const [functionName,value]of Object.entries(expected)){const actual=await client.readContract({address:r.adapter,abi:adapterContract(entry,routeArtifacts).abi,functionName,blockNumber:head});check(typeof value==='number'?Number(actual)===value:typeof actual==='string'&&actual.toLowerCase()===String(value).toLowerCase(),'ROUTE_IMMUTABLE_MISMATCH');}
  check((await client.getBlock({blockNumber:head})).hash===block.hash,'ROUTE_SNAPSHOT_REORGANIZED');
}

export async function createPhase2ASPService({client,profile,artifacts,directory,signer=null,routes=[],routeArtifacts,associationSet,associationSetLoader,quoteRoute,
  serviceFeePolicy=null,authorizeFee,settleFee,maxGas=3000000n,gasBudgetWei=100000000000000n,host='127.0.0.1',port=0,networkPolicy=createNetworkPolicy(),listen=true,httpOptions={},errorLogger,publisherStatusLoader,submissionControlLoader,associationSetFile}){
  const httpLimits=normalizeHttpLimits(httpOptions);
  check(errorLogger===undefined||typeof errorLogger==='function','INVALID_ERROR_LOGGER');check(publisherStatusLoader===undefined||typeof publisherStatusLoader==='function','INVALID_PUBLISHER_STATUS_LOADER');
  check(submissionControlLoader===undefined||typeof submissionControlLoader==='function','INVALID_SUBMISSION_CONTROL_LOADER');
  profile=structuredClone(profile);routes=structuredClone(routes);const feePolicy=serviceFeePolicy===null?null:normalizeServiceFeePolicy(serviceFeePolicy);
  normalizeProfile(profile);check(profile.schema!==PRODUCTION_PROFILE_SCHEMA,'MAINNET_SERVICE_ENTRY_REQUIRED');check(typeof maxGas==='bigint'&&maxGas>0n&&typeof gasBudgetWei==='bigint'&&gasBudgetWei>=0n,'INVALID_RELAY_LIMITS');
  check(!signer||profile.chain.id!==46630||typeof authorizeFee==='function'&&typeof settleFee==='function','PUBLIC_RELAY_SHARED_BUDGET_REQUIRED');
  const configuredRoutes=routesFor(profile,routes),availableRoutes=serviceRoutesForFeePolicy(configuredRoutes,feePolicy),identity=phase2Identity(profile),indexer=await createPhase2Indexer({client,profile,artifacts,directory:`${directory}/indexer`,associationSet,associationSetLoader});
  const routeAdapters=new Set(configuredRoutes.map(entry=>entry.route.adapter.toLowerCase()));
  const publicationEvents=createASPPublicationEvents({profile,associationSetFile,sync:()=>indexer.sync()});
  let store;try{store=await openServiceStore({directory:`${directory}/relay`,identity,filename:'jobs.json'});}catch(error){await indexer.close();throw error;}
  let state,tail=Promise.resolve(),queued=0,closed=false;
  try{state=await store.read()??{schema:'phase2-asp-relay-jobs/v1',identity,processor:signer?.address.toLowerCase()??null,jobs:[]};
    await validateRelayStore(state,{profile,artifacts,identity,processor:signer?.address,maxGas,gasBudgetWei,routes,routeArtifacts});if(state.processor===null&&signer)state.processor=address(signer.address);
  }catch(error){await Promise.allSettled([indexer.close(),store.close()]);throw error;}
  let persistedIds=new Set(state.jobs.map(job=>job.id)),persistenceUncertain=false;const activeSubmissions=new Map();
  const save=()=>relayStage('persistence',async()=>{try{await store.write(state);persistedIds=new Set(state.jobs.map(job=>job.id));persistenceUncertain=false;}catch(error){persistenceUncertain=true;throw error;}}),publicJob=job=>wire(Object.fromEntries(['id','kind','routeId','status','nonce','hash','blockHash','blockNumber','feeWei','feeCeilingWei'].filter(k=>Object.hasOwn(job,k)).map(k=>[k,job[k]])));
  const recovery=id=>relayJobRecovery({id,job:state.jobs.find(job=>job.id===id),persisted:persistedIds.has(id),uncertain:persistenceUncertain,inFlight:activeSubmissions.has(id)});
  const failure=(error,request={})=>relayErrorReply(error,{service:'phase2-asp',chainId:profile.chain.id,errorLogger,...request});
  let submissionControl={acceptingNewJobs:true,reason:'RELAY_ACCEPTING'};
  async function refreshSubmissionControl(){if(submissionControlLoader)try{const next=await submissionControlLoader();check(typeof next?.acceptingNewJobs==='boolean'&&['RELAY_ACCEPTING','RELAY_MIGRATION_DRAIN','RELAY_CLOUD_STAGED','RELAY_OPERATOR_PAUSED','RELAY_CONTROL_UNAVAILABLE'].includes(next.reason),'INVALID_SUBMISSION_CONTROL');submissionControl=next;}catch{submissionControl={acceptingNewJobs:false,reason:'RELAY_CONTROL_UNAVAILABLE'};}return {...submissionControl,acceptingNewJobs:Boolean(signer)&&!closed&&submissionControl.acceptingNewJobs,inFlight:activeSubmissions.size,unsettledJobs:state.jobs.filter(j=>!['confirmed','reverted'].includes(j.status)).length};}
  const submissionSnapshot=()=>({...submissionControl,acceptingNewJobs:Boolean(signer)&&!closed&&submissionControl.acceptingNewJobs,inFlight:activeSubmissions.size,unsettledJobs:state.jobs.filter(j=>!['confirmed','reverted'].includes(j.status)).length});
  const exclusive=fn=>{check(queued<16,'RELAY_REQUEST_QUEUE_FULL');queued++;const run=tail.then(fn).finally(()=>{queued--;});tail=run.catch(()=>{});return run;};
  async function reconcile(){for(const job of state.jobs.filter(j=>j.status!=='preparing')){const receipt=await verifyRelayReceipt(job,{client,processor:state.processor});if(!receipt)continue;
    if(settleFee)await settleFee({identity,job:wire(job),receipt});if(['confirmed','reverted'].includes(job.status))continue;
    job.status=receipt.status==='success'?'confirmed':'reverted';job.blockHash=receipt.blockHash;job.blockNumber=String(receipt.blockNumber);job.feeWei=String(receipt.gasUsed*receipt.effectiveGasPrice);await save();}}
  async function submit(body){const id=validRelayJobId(body?.id)?body.id:null;await refreshSubmissionControl();if(!state.jobs.some(job=>job.id===id))check(submissionControl.acceptingNewJobs,'RELAY_DRAINING');if(id)activeSubmissions.set(id,(activeSubmissions.get(id)??0)+1);
    try{return await submitIntent(body);}finally{if(id){const remaining=activeSubmissions.get(id)-1;if(remaining)activeSubmissions.set(id,remaining);else activeSubmissions.delete(id);}}}
  async function submitIntent(body){check(signer&&!closed,'RELAY_DISABLED');const intent=await relayStage('validation',()=>validateRelayRequest(body,{profile,artifacts,processor:signer.address,routes,routeArtifacts}));
    return exclusive(async()=>{await relayStage('reconcile',reconcile);const existing=state.jobs.find(j=>j.id===intent.id);if(existing){check(existing.fingerprint===intent.fingerprint,'ID_CONFLICT');return publicJob(existing);}
      await refreshSubmissionControl();check(submissionControl.acceptingNewJobs,'RELAY_DRAINING');
      validateCommercialFee(intent,feePolicy);
      check(!state.jobs.some(j=>['signed','pending','preparing'].includes(j.status)),'RELAY_UNRESOLVED_TRANSACTION');check(state.jobs.length<MAX_JOBS,'RELAY_CAPACITY_REACHED');
      check(!state.jobs.some(j=>j.status!=='reverted'&&j.nullifiers.some(n=>intent.nullifiers.includes(n))),'NULLIFIER_RESERVED');
      const snapshot=await relayStage('state',()=>indexer.sync());validateIntentState(intent,snapshot,{profile,routeAdapters});await assertRagequitRecipient(client,intent,{profile,routeAdapters,blockNumber:BigInt(snapshot.blockNumber)});
      if(['transact','swap'].includes(intent.kind))check(await client.readContract({address:profile.pool.address,abi:artifacts.Phase2ASPPool.abi,functionName:'knownRoot',args:[intent.signals[0]]}),'UNKNOWN_PROOF_ROOT');
      if(intent.routeEntry)await verifyRouteLive(client,intent.routeEntry,routeArtifacts);
      const latest=await client.getTransactionCount({address:signer.address}),pending=await client.getTransactionCount({address:signer.address,blockTag:'pending'});check(latest===pending,'PENDING_NONCE');
      const tx={account:signer.address,to:intent.to,data:intent.data,value:0n},estimate=await relayStage('estimate',()=>client.estimateGas(tx)),gas=estimate*12n/10n+10000n;check(gas<=maxGas,'RELAY_GAS_LIMIT');
      const gasPrice=(await client.getGasPrice())||1n,feeCeilingWei=gas*gasPrice,reserved=state.jobs.reduce((sum,j)=>sum+BigInt(j.feeWei??j.feeCeilingWei),0n);check(reserved+feeCeilingWei<=gasBudgetWei,'RELAY_GAS_BUDGET');
      const job={id:intent.id,kind:intent.kind,routeId:intent.routeId,fingerprint:intent.fingerprint,nullifiers:intent.nullifiers,status:'preparing',nonce:latest,feeCeilingWei:String(feeCeilingWei),data:intent.data,to:intent.to,chainId:profile.chain.id,gas:String(gas),gasPrice:String(gasPrice)};
      if(authorizeFee)await relayStage('budget',()=>authorizeFee({identity,jobId:job.id,processor:signer.address,chainId:profile.chain.id,nonce:latest,gas,gasPrice,feeCeilingWei,to:intent.to,data:intent.data}));
      state.jobs.push(job);await save();
      const raw=await relayStage('signing',()=>signer.signTransaction({chainId:profile.chain.id,to:intent.to,data:intent.data,value:0n,nonce:latest,gas,gasPrice,type:'legacy'})),parsed=parseTransaction(raw),recovered=await recoverTransactionAddress({serializedTransaction:raw});
      check(parsed.type==='legacy'&&parsed.chainId===profile.chain.id&&parsed.to?.toLowerCase()===intent.to&&parsed.data===intent.data&&(parsed.value??0n)===0n&&(parsed.nonce??0)===latest&&parsed.gas===gas&&parsed.gasPrice===gasPrice&&recovered.toLowerCase()===signer.address.toLowerCase(),'SIGNED_INTENT_MISMATCH');
      job.raw=raw;job.hash=keccak256(raw);job.status='signed';await save();
      try{const hash=await relayStage('broadcast',()=>client.sendRawTransaction({serializedTransaction:raw}));check(hash===job.hash,'BROADCAST_HASH_MISMATCH');job.status='pending';await save();}catch(error){failure(error,{method:'POST',path:'/v3/jobs',jobRecovery:recovery(intent.id)});job.status='pending';await save();}
      await relayStage('reconcile',reconcile);return publicJob(job);});}
  const unknownPublisher=()=>structuredClone(DEFAULT_PUBLISHER_STATUS);
  let publisherStatus=unknownPublisher();async function refreshPublisher(snapshot){if(publisherStatusLoader)try{publisherStatus=await publisherStatusLoader(snapshot);}catch{publisherStatus=unknownPublisher();}return structuredClone(publisherStatus);}
  const config=()=>({profile,processor:signer?.address??null,routes:availableRoutes.map(({id,route,targetProfile})=>({id,route,targetProfile})),serviceFees:feePolicy,relaySigning:Boolean(signer),submission:submissionSnapshot(),associationPolicy:'current-note',publicExitsRequireASP:false,...structuredClone(publisherStatusLoader?.snapshot?.()??publisherStatus),testOnly:true,productionReady:false});
  async function quote(body){exact(body,['routeId','amountIn','slippageBPS']);check(typeof body.routeId==='string','INVALID_ROUTE_ID');const entry=availableRoutes.find(r=>r.id===body.routeId);check(entry&&typeof quoteRoute==='function','QUOTE_UNAVAILABLE');const amountIn=integer(body.amountIn,MAX128);check(amountIn>0n&&Number.isSafeInteger(body.slippageBPS)&&body.slippageBPS>=1&&body.slippageBPS<=500,'INVALID_QUOTE_LIMITS');return quoteRoute({client,sourceProfile:profile,targetProfile:entry.targetProfile,route:{...entry.route,id:entry.id},amountIn,slippageBPS:body.slippageBPS});}
  function fees(body){exact(body,['kind','grossAmount']);check(feePolicy!==null,'SERVICE_FEE_POLICY_DISABLED');return quoteServiceFee({policy:feePolicy,kind:body.kind,grossAmount:body.grossAmount});}
  async function aggregateQuote(body){
    exact(body,['targetPool','amountIn','slippageBPS']);const targetPool=address(body.targetPool),amountIn=integer(body.amountIn,MAX128);
    check(amountIn>0n&&Number.isSafeInteger(body.slippageBPS)&&body.slippageBPS>=1&&body.slippageBPS<=500,'INVALID_QUOTE_LIMITS');
    const selected=availableRoutes.filter(entry=>entry.geometry.targetPool===targetPool);check(selected.length>0&&typeof quoteRoute==='function','QUOTE_UNAVAILABLE');
    return quotePhase2Aggregate({client,sourceProfile:profile,targetProfile:selected[0].targetProfile,routes:selected,amountIn,slippageBPS:body.slippageBPS,quoteRoute,
      feeBpsForRoute:entry=>FEE_ADAPTER_TYPES.includes(entry.route.adapterType)?entry.route.feeBps:0});
  }
  const quoteGate=createQuoteGate();
  const json=(res,status,value)=>serviceJson(res,status,wire(value));
  async function readBody(req){check(req.headers['content-type']?.split(';')[0]==='application/json','JSON_REQUIRED');let length=0;const chunks=[];for await(const chunk of req){length+=chunk.length;check(length<=32768,'BODY_TOO_LARGE');chunks.push(chunk);}try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new Error('INVALID_JSON');}}
  const server=createBoundedHttpServer(async(req,res)=>{const jobRead=req.method==='GET'&&/^\/v3\/jobs\/[A-Za-z0-9_-]{8,80}$/.test(req.url);let jobId=jobRead?req.url.split('/').at(-1):null;const jobRequest=req.method==='POST'&&req.url==='/v3/jobs';res.relayErrorReply=error=>failure(error,{method:req.method,path:req.url,jobRecovery:jobRequest||jobRead?{...recovery(jobId),...(jobRequest&&error.message==='REQUEST_DEADLINE_EXCEEDED'?{jobMayContinue:true,retrySameId:false}:{})}:undefined});try{check(networkPolicy.allows(req.headers.host,req.headers.origin),'HOST_OR_ORIGIN_DENIED');const url=new URL(req.url,'http://127.0.0.1');check(!url.search,'QUERY_NOT_SUPPORTED');
    if(url.pathname==='/v3/events'){
      if(req.method!=='GET')return json(res,405,{error:'METHOD_NOT_ALLOWED'});
      if(!publicationEvents.subscribe(req,res))return json(res,503,{error:'ASP_EVENTS_UNAVAILABLE'});
      return;
    }
    if(req.method==='GET'&&url.pathname==='/livez')return json(res,200,{ok:true});
    if(req.method==='GET'&&['/healthz','/readyz','/v3/readyz'].includes(url.pathname)){const s=await indexer.sync();const submission=await refreshSubmissionControl();return json(res,200,{ok:true,submission,chainId:profile.chain.id,blockNumber:s.blockNumber,relaySigning:Boolean(signer),normalSpendingReady:!s.asp.expired&&s.asp.spendable!==false&&Array.isArray(s.asp.leaves),publicExitsReady:true,asp:{root:s.asp.root,epoch:s.asp.epoch,validUntil:s.asp.validUntil,expired:s.asp.expired,setAvailable:Array.isArray(s.asp.leaves)},...await refreshPublisher(s),testOnly:true,productionReady:false});}
    if(req.method==='GET'&&url.pathname==='/v3/config'){await refreshPublisher(await indexer.sync());await refreshSubmissionControl();return json(res,200,config());}
    if(req.method==='GET'&&url.pathname==='/v3/state'){const{checkpoint,...publicState}=await indexer.sync();return json(res,200,{...publicState,...await refreshPublisher(publicState)});}
    if(req.method==='GET'&&url.pathname==='/v3/association-set'){const s=await indexer.sync();check(Array.isArray(s.asp.leaves),'ASSOCIATION_SET_UNAVAILABLE');return json(res,200,{schema:'phase2-asp-association-set/v1',chainId:s.chainId,pool:s.pool,blockNumber:s.blockNumber,blockHash:s.blockHash,...s.asp});}
    if(req.method==='POST'&&url.pathname==='/v3/jobs'){const request=await readBody(req);jobId=validRelayJobId(request?.id)?request.id:null;const job=await submit(request);return json(res,200,{...job,...recovery(jobId)});}
    if(req.method==='POST'&&url.pathname==='/v3/quote'){const request=await readBody(req);return json(res,200,await relayStage('quote',()=>quoteGate(()=>quote(request))));}
    if(req.method==='POST'&&url.pathname==='/v3/fees')return json(res,200,fees(await readBody(req)));
    if(req.method==='POST'&&url.pathname==='/v3/aggregate-quote'){const request=await readBody(req);return json(res,200,await relayStage('quote',()=>quoteGate(()=>aggregateQuote(request))));}
    if(req.method==='GET'&&/^\/v3\/jobs\/[A-Za-z0-9_-]{8,80}$/.test(url.pathname)){const result=await exclusive(async()=>{await reconcile();const job=state.jobs.find(j=>j.id===url.pathname.split('/').at(-1));check(job,'JOB_NOT_FOUND');return publicJob(job);});return json(res,200,{...result,...recovery(jobId)});}
    return json(res,404,{error:'NOT_FOUND'});
  }catch(error){const reply=res.relayErrorReply(error);json(res,reply.status,reply.body);}},httpLimits);
  try{await reconcile();await refreshPublisher(await indexer.sync());await refreshSubmissionControl();if(listen)await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});}catch(error){await Promise.allSettled([indexer.close(),store.close()]);throw error;}
  return{port:listen?server.address().port:null,host,submit,quote,fees,aggregateQuote,config,sync:()=>indexer.sync(),async job(id){return exclusive(async()=>{await reconcile();const found=state.jobs.find(j=>j.id===id);check(found,'JOB_NOT_FOUND');return publicJob(found);});},async close(){closed=true;await publicationEvents.close();if(listen)await new Promise(resolve=>server.close(resolve));await tail;await indexer.close();await store.close();}};
}
export const createPhase2Service=createPhase2ASPService;
// Reused by the production HTTP adapter; these never sign or broadcast.
export {routesFor as normalizeServiceRoutes,verifyRouteLive};
