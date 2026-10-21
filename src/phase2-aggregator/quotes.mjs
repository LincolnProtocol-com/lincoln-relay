// SPDX-License-Identifier: Apache-2.0
// Read-only selection among already configured, independently pinned routes.
// This is not a path finder, a split router, or a permission to execute calldata.
import {isAddress} from 'viem';
import {MAX_VALUE, NATIVE_ASSET, normalizeProfile, normalizeSwapRoute} from '../phase2-asp/sdk.mjs';
import {quotePhase2Route} from '../phase2-asp/quote.mjs';
import {DEFAULT_SERVICE_FEE_BPS,MAX_SERVICE_FEE_BPS,Phase2AggregateQuoteError,netPhase2Quote} from './amounts.mjs';
export {DEFAULT_SERVICE_FEE_BPS,MAX_SERVICE_FEE_BPS,Phase2AggregateQuoteError,netPhase2Quote} from './amounts.mjs';

const MAX_UINT256=(1n<<256n)-1n;
function must(value,code){if(!value)throw new Phase2AggregateQuoteError(code);}
function same(a,b){return typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();}
function address(value){must(isAddress(value),'INVALID_AGGREGATE_ADDRESS');return value.toLowerCase();}
function hash(value){must(typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value)&&!/^0x0{64}$/i.test(value),'INVALID_AGGREGATE_HASH');return value.toLowerCase();}
function integer(value,max=MAX_UINT256){
  must(typeof value==='bigint'||typeof value==='number'&&Number.isSafeInteger(value)||typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value),'INVALID_AGGREGATE_INTEGER');
  const result=BigInt(value);must(result>=0n&&result<=max,'INVALID_AGGREGATE_INTEGER');return result;
}
function publicError(error){
  const code=error?.code??error?.message;
  return typeof code==='string'&&/^[A-Z][A-Z0-9_]{1,79}$/.test(code)?code:'ROUTE_QUOTE_FAILED';
}
function endpoint(profile){
  let result;try{result=normalizeProfile(profile);}catch{throw new Phase2AggregateQuoteError('INVALID_AGGREGATE_PROFILE');}
  return {...result,genesisHash:hash(profile.genesisHash)};
}
function sameEndpoint(a,b){return a.chainId===b.chainId&&a.pool===b.pool&&a.asset===b.asset&&a.scope===b.scope&&a.registry===b.registry&&a.provider===b.provider&&a.genesisHash===b.genesisHash;}
function ceiling(numerator,denominator){return (numerator+denominator-1n)/denominator;}

async function bounded(items,limit,task){
  const results=new Array(items.length);let cursor=0;
  await Promise.all(Array.from({length:Math.min(limit,items.length)},async()=>{
    while(cursor<items.length){const index=cursor++;results[index]=await task(items[index],index);}
  }));
  return results;
}
async function blockAt(client,blockNumber){
  const block=await client.getBlock({blockNumber});
  must(integer(block?.number)===blockNumber,'AGGREGATE_BLOCK_NUMBER_MISMATCH');
  return {blockNumber,blockHash:hash(block.hash),timestamp:integer(block.timestamp)};
}
function normalizeGasConversion(value,{source,target,snapshot}){
  if(value===undefined)return null;
  must(value&&typeof value==='object'&&!Array.isArray(value),'INVALID_AGGREGATE_GAS_CONVERSION');
  must(value.chainId===source.chainId&&address(value.targetAsset)===target.asset&&integer(value.blockNumber)===snapshot.blockNumber&&hash(value.blockHash)===snapshot.blockHash,'AGGREGATE_GAS_CONVERSION_SNAPSHOT_MISMATCH');
  must(typeof value.source==='string'&&value.source.length>=1&&value.source.length<=160,'INVALID_AGGREGATE_GAS_CONVERSION_SOURCE');
  const numerator=integer(value.numerator),denominator=integer(value.denominator);
  must(numerator>0n&&denominator>0n,'INVALID_AGGREGATE_GAS_CONVERSION');
  return {chainId:source.chainId,targetAsset:target.asset,blockNumber:snapshot.blockNumber,blockHash:snapshot.blockHash,source:value.source,numerator,denominator};
}

/**
 * Compare exact-input quotes for ONE chain, source pool, target pool and amount.
 *
 * routes is the existing service-side array of {id,route,targetProfile}; entries
 * for another target are reported as excluded, never compared. quoteRoute is a
 * trusted read-only implementation, defaulting to the pinned ASP route quoter.
 * Each accepted quote must preserve its configured topology and the common
 * canonical snapshot. No old quote cache is accepted.
 * feeBpsForRoute, if provided, is trusted server-side configuration captured
 * before RPC. It must reflect the executable adapter's immutable fee. In
 * particular existing zero-fee adapters must use 0, not a planned future fee.
 *
 * executionCostNative, if provided, is a trusted server-side callback returning
 * the complete call's native-wei cost (bigint), or {nativeCost,gasUnits,source}.
 * Existing DEX Quoter gasEstimate is only informational: it omits privacy-pool,
 * verifier and adapter execution and MUST NOT be treated as a complete estimate.
 * gasConversion is a trusted server-side, same-snapshot rational conversion in
 * output base units per native wei. Output native ETH, or an explicitly pinned
 * wrappedNativeAsset, can use the 1:1 native-wei conversion instead. Costs round
 * UP. If any accepted route lacks a comparable complete cost, ALL routes rank
 * by post-service-fee output and the result explicitly excludes gas from ranking.
 *
 * This function does not sign, approve, broadcast, or produce a spend proof.
 */
/** Fail-fast cap on concurrent public quote requests. Each quote fans out to
 * dozens of RPC reads per route and the HTTP endpoints are unauthenticated,
 * so excess requests are refused (QUOTE_BUSY) instead of queued.
 */
export function createQuoteGate(maxInFlight=4){
  if(!Number.isSafeInteger(maxInFlight)||maxInFlight<1||maxInFlight>64)throw new Phase2AggregateQuoteError('INVALID_QUOTE_CONCURRENCY');
  let active=0;
  return async run=>{
    if(active>=maxInFlight)throw new Phase2AggregateQuoteError('QUOTE_BUSY');
    active++;
    try{return await run();}finally{active--;}
  };
}

export async function quotePhase2Aggregate({client,sourceProfile,targetProfile,routes,amountIn,slippageBPS=100,
  serviceFeeBps=DEFAULT_SERVICE_FEE_BPS,deadlineSeconds=600,blockNumber:requestedBlock,blockHash:requestedHash,
  concurrency=3,quoteRoute=quotePhase2Route,feeBpsForRoute,executionCostNative,gasConversion,wrappedNativeAsset}={}){
  const captured=structuredClone({sourceProfile,targetProfile,routes,gasConversion});
  const source=endpoint(captured.sourceProfile),target=endpoint(captured.targetProfile);
  must(source.chainId===target.chainId&&source.genesisHash===target.genesisHash&&source.pool!==target.pool,'AGGREGATE_POOL_NETWORK_MISMATCH');
  must(typeof amountIn==='bigint'&&amountIn>0n&&amountIn<=MAX_VALUE,'INVALID_AGGREGATE_INPUT');
  must(Number.isSafeInteger(serviceFeeBps)&&serviceFeeBps>=0&&serviceFeeBps<=MAX_SERVICE_FEE_BPS,'INVALID_AGGREGATE_FEE');
  must(Number.isSafeInteger(slippageBPS)&&slippageBPS>=1&&slippageBPS<=500,'INVALID_AGGREGATE_SLIPPAGE');
  must(Number.isSafeInteger(deadlineSeconds)&&deadlineSeconds>=1&&deadlineSeconds<=3600,'INVALID_AGGREGATE_DEADLINE');
  must(Number.isSafeInteger(concurrency)&&concurrency>=1&&concurrency<=4,'INVALID_AGGREGATE_CONCURRENCY');
  must(Array.isArray(captured.routes)&&captured.routes.length>0&&captured.routes.length<=64,'INVALID_AGGREGATE_ROUTES');
  must(captured.routes.every(entry=>entry&&typeof entry.id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(entry.id))&&new Set(captured.routes.map(entry=>entry.id)).size===captured.routes.length,'INVALID_AGGREGATE_ROUTE_IDS');
  must(typeof quoteRoute==='function'&&(feeBpsForRoute===undefined||typeof feeBpsForRoute==='function')&&(executionCostNative===undefined||typeof executionCostNative==='function'),'INVALID_AGGREGATE_CALLBACK');
  const routeFees=captured.routes.map(entry=>feeBpsForRoute?feeBpsForRoute(structuredClone(entry)):serviceFeeBps);
  must(routeFees.every(value=>Number.isSafeInteger(value)&&value>=0&&value<=MAX_SERVICE_FEE_BPS),'INVALID_AGGREGATE_FEE');
  const uniformFee=new Set(routeFees).size===1?routeFees[0]:null;
  for(const method of ['getChainId','getBlockNumber','getBlock'])must(typeof client?.[method]==='function','INVALID_AGGREGATE_CLIENT');
  const wrapped=wrappedNativeAsset===undefined?null:address(wrappedNativeAsset);
  must(wrapped!==NATIVE_ASSET,'INVALID_AGGREGATE_WRAPPED_NATIVE');
  // Reject syntactically bad block identifiers before contacting the provider.
  const requested=requestedBlock===undefined?undefined:integer(requestedBlock),expectedHash=requestedHash===undefined?null:hash(requestedHash);
  must(await client.getChainId()===source.chainId,'AGGREGATE_CHAIN_MISMATCH');
  const head=integer(await client.getBlockNumber({cacheTime:0})),blockNumber=requested??head;
  must(blockNumber<=head,'AGGREGATE_BLOCK_AFTER_HEAD');
  const snapshot=await blockAt(client,blockNumber),genesis=await blockAt(client,0n);
  must(genesis.blockHash===source.genesisHash,'AGGREGATE_GENESIS_MISMATCH');
  must(expectedHash===null||expectedHash===snapshot.blockHash,'AGGREGATE_REQUESTED_SNAPSHOT_MISMATCH');
  const conversion=normalizeGasConversion(captured.gasConversion,{source,target,snapshot});
  const deadline=snapshot.timestamp+BigInt(deadlineSeconds);
  must(deadline<=MAX_UINT256,'AGGREGATE_DEADLINE_OVERFLOW');
  const candidates=await bounded(captured.routes,concurrency,async(entry,index)=>{
    const routeId=entry.id,routeFee=routeFees[index];
    let route,geometry;
    try{
      if(entry.route?.executionEnabled===false)return {routeId,serviceFeeBps:routeFee,status:'excluded',error:'AGGREGATE_ROUTE_DISABLED'};
      must(entry.route?.executionEnabled===undefined||entry.route.executionEnabled===true,'INVALID_AGGREGATE_ROUTE_EXECUTION_FLAG');
      const entryTarget=endpoint(entry.targetProfile);
      if(!sameEndpoint(entryTarget,target))return {routeId,serviceFeeBps:routeFee,status:'excluded',error:'AGGREGATE_TARGET_MISMATCH'};
      must(entry.route&&typeof entry.route==='object'&&!Array.isArray(entry.route),'INVALID_AGGREGATE_ROUTE');
      must(entry.route.id===undefined||entry.route.id===routeId,'AGGREGATE_ROUTE_ID_MISMATCH');
      route={...entry.route,id:routeId};
      geometry=normalizeSwapRoute({sourceProfile:captured.sourceProfile,targetProfile:captured.targetProfile,route});
      must(route.sourcePool===undefined||same(route.sourcePool,source.pool),'AGGREGATE_SOURCE_MISMATCH');
    }catch(error){return {routeId,serviceFeeBps:routeFee,status:'failed',error:publicError(error)};}
    try{
      // A clone prevents an injected quoter from mutating siblings' configuration.
      const grossQuote=await quoteRoute({client,sourceProfile:structuredClone(captured.sourceProfile),targetProfile:structuredClone(captured.targetProfile),route:structuredClone(route),amountIn,slippageBPS,deadlineSeconds,blockNumber});
      must(grossQuote&&grossQuote.routeId===routeId&&grossQuote.chainId===source.chainId&&same(grossQuote.sourcePool,source.pool)&&same(grossQuote.targetPool,target.pool)&&same(grossQuote.sourceAsset,source.asset)&&same(grossQuote.targetAsset,target.asset),'AGGREGATE_QUOTE_SCOPE_MISMATCH');
      must(integer(grossQuote.amountIn)===amountIn&&integer(grossQuote.blockNumber)===blockNumber&&hash(grossQuote.blockHash)===snapshot.blockHash,'AGGREGATE_QUOTE_SNAPSHOT_MISMATCH');
      must(same(grossQuote.adapter,geometry.adapter)&&same(grossQuote.router,geometry.router)&&same(grossQuote.factory,geometry.factory)&&same(grossQuote.wrappedNative,geometry.wrappedNative)&&same(grossQuote.path,geometry.path),'AGGREGATE_QUOTE_ROUTE_MISMATCH');
      must(grossQuote.slippageBPS===slippageBPS&&integer(grossQuote.deadline)===deadline&&grossQuote.transactionsSent===false,'AGGREGATE_QUOTE_LIMITS_MISMATCH');
      const grossAmountOut=integer(grossQuote.amountOut,MAX_VALUE),netQuote=netPhase2Quote({grossAmountOut,serviceFeeBps:routeFee,slippageBPS});
      const candidate={routeId,serviceFeeBps:routeFee,status:'quoted',grossQuote:structuredClone(grossQuote),netQuote,quoteGasKind:'dex-quoter-only',
        quotedNativeExecutionCost:null,totalExecutionGas:null,executionCostSource:null,executionCostInOutput:null,gasIncluded:false,rankingAmountOut:netQuote.netAmountOut};
      if(executionCostNative){
        try{
          const supplied=await executionCostNative({route:structuredClone(route),quote:structuredClone(grossQuote),snapshot:structuredClone(snapshot)});
          const cost=typeof supplied==='bigint'?supplied:supplied?.nativeCost;
          must(typeof cost==='bigint','INVALID_AGGREGATE_EXECUTION_COST');
          candidate.quotedNativeExecutionCost=integer(cost);
          if(typeof supplied==='object'){
            if(supplied.gasUnits!==undefined)candidate.totalExecutionGas=integer(supplied.gasUnits);
            if(supplied.source!==undefined)must(typeof supplied.source==='string'&&supplied.source.length>=1&&supplied.source.length<=160,'INVALID_AGGREGATE_EXECUTION_COST_SOURCE');
            candidate.executionCostSource=supplied.source??'caller-supplied-complete-execution-estimate';
          }else candidate.executionCostSource='caller-supplied-complete-execution-estimate';
          if(target.asset===NATIVE_ASSET||wrapped!==null&&target.asset===wrapped&&geometry.wrappedNative===wrapped){
            candidate.executionCostInOutput=candidate.quotedNativeExecutionCost;
          }else if(conversion){
            candidate.executionCostInOutput=ceiling(candidate.quotedNativeExecutionCost*conversion.numerator,conversion.denominator);
            must(candidate.executionCostInOutput<=MAX_UINT256,'AGGREGATE_CONVERTED_COST_OVERFLOW');
          }
        }catch(error){
          candidate.quotedNativeExecutionCost=null;candidate.totalExecutionGas=null;candidate.executionCostSource=null;candidate.executionCostInOutput=null;candidate.executionCostError=publicError(error);
        }
      }
      return candidate;
    }catch(error){return {routeId,serviceFeeBps:routeFee,status:'failed',error:publicError(error)};}
  });
  must((await blockAt(client,blockNumber)).blockHash===snapshot.blockHash&&await client.getChainId()===source.chainId,'AGGREGATE_SNAPSHOT_CHANGED');
  const quoted=candidates.filter(candidate=>candidate.status==='quoted');
  const gasIncluded=quoted.length>0&&quoted.every(candidate=>candidate.executionCostInOutput!==null);
  for(const candidate of quoted){candidate.gasIncluded=gasIncluded;candidate.rankingAmountOut=candidate.netQuote.netAmountOut-(gasIncluded?candidate.executionCostInOutput:0n);}
  const ranked=[...quoted].sort((a,b)=>a.rankingAmountOut===b.rankingAmountOut?a.routeId.localeCompare(b.routeId):a.rankingAmountOut>b.rankingAmountOut?-1:1);
  const selected=ranked[0]??null;
  return {schema:'phase2-aggregate-quote/v1',chainId:source.chainId,sourcePool:source.pool,targetPool:target.pool,sourceAsset:source.asset,targetAsset:target.asset,
    amountIn,serviceFeeBps:uniformFee,serviceFeePolicy:uniformFee===null?'per-route':'uniform',slippageBPS,snapshot,deadline,candidates,rankedRouteIds:ranked.map(candidate=>candidate.routeId),selectedRouteId:selected?.routeId??null,selected,
    rankingBasis:gasIncluded?'post-service-fee-output-less-quoted-execution-cost':'post-service-fee-output-gas-excluded',gasIncludedInRanking:gasIncluded,
    gasConversion:conversion,scope:'configured-routes-only',splitRouting:false,transactionsSent:false};
}
