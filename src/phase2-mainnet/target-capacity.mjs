// SPDX-License-Identifier: Apache-2.0
// Prepared read-only helper; NOT imported by the current production quote/relay.
import {keccak256,parseAbi} from 'viem';
import {normalizeProfile} from '../phase2-asp/sdk.mjs';

const UINT128=(1n<<128n)-1n,UINT256=(1n<<256n)-1n;
const ADDRESS=/^0x[a-f0-9]{40}$/i,HASH=/^0x[a-f0-9]{64}$/i;
const CAP_ABI=parseAbi(['function maxDeposit() view returns(uint128)','function maxTotal() view returns(uint128)',
  'function accountedBalance() view returns(uint256)','function depositsPaused() view returns(bool)','function nextLeafIndex() view returns(uint256)',
  'function ASSET() view returns(address)','function SCOPE() view returns(uint256)']);
export class TargetCapacityError extends Error{constructor(code){super(code);this.name='TargetCapacityError';this.code=code;}}
const need=(ok,code)=>{if(!ok)throw new TargetCapacityError(code);};
function integer(value,max=UINT256,{positive=false}={}){
  need(typeof value==='bigint'||typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value),'INVALID_TARGET_CAPACITY_INTEGER');
  const number=BigInt(value);need(number>=(positive?1n:0n)&&number<=max,'INVALID_TARGET_CAPACITY_INTEGER');return number;
}
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
function normalizeSnapshot(snapshot){
  need(snapshot?.schema==='lincoln-target-capacity-snapshot/v1'&&Number.isSafeInteger(snapshot.chainId)&&snapshot.chainId>0
    &&ADDRESS.test(snapshot.pool??'')&&ADDRESS.test(snapshot.asset??'')&&HASH.test(snapshot.blockHash??''),'INVALID_TARGET_CAPACITY_SNAPSHOT');
  need(typeof snapshot.depositsPaused==='boolean'&&Number.isSafeInteger(snapshot.treeDepth)&&snapshot.treeDepth===20,'INVALID_TARGET_CAPACITY_SNAPSHOT');
  const maxDeposit=integer(snapshot.maxDeposit,UINT128,{positive:true}),maxTotal=integer(snapshot.maxTotal,UINT128,{positive:true}),accountedBalance=integer(snapshot.accountedBalance);
  need(maxDeposit<=maxTotal,'INVALID_TARGET_CAPACITY_LIMITS');
  return {...snapshot,maxDeposit,maxTotal,accountedBalance,blockNumber:integer(snapshot.blockNumber),nextLeafIndex:integer(snapshot.nextLeafIndex)};
}

/** Exact depositDynamic bounds, applied to the NET amount actually reshielded.
 * A snapshot accepts no reservation. Other deposits and price improvement can
 * still make a later fill exceed a cap; keep the full-call simulation gate. */
export function assessTargetDepositCapacity({netAmountOut,snapshot}={}){
  const s=normalizeSnapshot(snapshot),net=integer(netAmountOut,UINT128,{positive:true});
  const remainingTotal=s.accountedBalance>=s.maxTotal?0n:s.maxTotal-s.accountedBalance;
  const maximumNetDeposit=s.maxDeposit<remainingTotal?s.maxDeposit:remainingTotal;
  const reasons=[];
  if(s.depositsPaused)reasons.push('TARGET_DEPOSITS_PAUSED');
  if(net>s.maxDeposit)reasons.push('TARGET_DEPOSIT_CAP_EXCEEDED');
  if(net>remainingTotal)reasons.push('TARGET_TOTAL_CAP_EXCEEDED');
  if(s.nextLeafIndex>=1n<<BigInt(s.treeDepth))reasons.push('TARGET_TREE_FULL');
  return {schema:'lincoln-target-deposit-capacity/v1',chainId:s.chainId,targetPool:s.pool,asset:s.asset,
    blockNumber:String(s.blockNumber),blockHash:s.blockHash,netAmountOut:String(net),maxDeposit:String(s.maxDeposit),maxTotal:String(s.maxTotal),
    accountedBalance:String(s.accountedBalance),remainingTotal:String(remainingTotal),maximumNetDeposit:String(maximumNetDeposit),
    depositsPaused:s.depositsPaused,treeFull:s.nextLeafIndex>=1n<<BigInt(s.treeDepth),fitsAtSnapshot:reasons.length===0,reasons,
    capacityReserved:false,executionGuaranteed:false,mustRecheckBeforeProofAndSubmission:true,upsideFillMayExceedCap:true,
    integrationStatus:'prepared-not-integrated',transactionsSent:false};
}

/** Accepts the current route quote shape. Uses expected NET, never slippage's
 * minNetOut: a lower minimum cannot make an over-cap expected deposit valid. */
export function assessQuoteTargetCapacity({quote,snapshot}={}){
  const s=normalizeSnapshot(snapshot);
  need(quote&&quote.chainId===s.chainId&&same(quote.targetPool,s.pool)&&same(quote.targetAsset,s.asset)
    &&integer(quote.blockNumber)===s.blockNumber&&same(quote.blockHash,s.blockHash),'TARGET_CAPACITY_QUOTE_SNAPSHOT_MISMATCH');
  need(Number.isSafeInteger(quote.serviceFeeBps)&&quote.serviceFeeBps>=0&&quote.serviceFeeBps<=100,'INVALID_TARGET_CAPACITY_FEE');
  const gross=integer(quote.amountOut,UINT128,{positive:true}),fee=gross*BigInt(quote.serviceFeeBps)/10000n,net=gross-fee;
  if(quote.netQuote!==undefined){
    need(integer(quote.netQuote.grossAmountOut)===gross&&integer(quote.netQuote.netAmountOut)===net
      &&integer(quote.netQuote.serviceFeeAmount)===fee&&quote.netQuote.serviceFeeBps===quote.serviceFeeBps,'TARGET_CAPACITY_QUOTE_FEE_MISMATCH');
  }
  return {...assessTargetDepositCapacity({netAmountOut:net,snapshot:s}),grossAmountOut:String(gross),serviceFeeBps:quote.serviceFeeBps,serviceFeeAmount:String(fee)};
}

export function assertQuotedTargetCapacity(options){
  const result=assessQuoteTargetCapacity(options);need(result.fitsAtSnapshot,result.reasons[0]);return result;
}

/** Canonical bounded snapshot. Caller supplies a verified target profile and
 * the quote's exact block/hash. Missing getters/RPC errors fail closed; there is
 * no fallback to constructor caps, wallet balances, TVL estimates or pending caps. */
export async function readTargetCapacitySnapshot({client,targetProfile,blockNumber,blockHash}={}){
  const p=normalizeProfile(targetProfile),height=integer(blockNumber),expectedHash=blockHash;
  need(HASH.test(expectedHash??'')&&HASH.test(targetProfile.pool?.runtimeCodeHash??''),'INVALID_TARGET_CAPACITY_SNAPSHOT');
  for(const method of ['getChainId','getBlock','getCode','readContract'])need(typeof client?.[method]==='function','INVALID_TARGET_CAPACITY_CLIENT');
  need(await client.getChainId()===p.chainId,'TARGET_CAPACITY_CHAIN_MISMATCH');
  const before=await client.getBlock({blockNumber:height});
  need(integer(before.number)===height&&same(before.hash,expectedHash),'TARGET_CAPACITY_BLOCK_MISMATCH');
  const code=await client.getCode({address:p.pool,blockNumber:height});
  need(typeof code==='string'&&/^0x(?:[a-f0-9]{2})+$/i.test(code)&&same(keccak256(code),targetProfile.pool.runtimeCodeHash),'TARGET_CAPACITY_RUNTIME_MISMATCH');
  const names=['maxDeposit','maxTotal','accountedBalance','depositsPaused','nextLeafIndex','ASSET','SCOPE'];
  const values=await Promise.all(names.map(functionName=>client.readContract({address:p.pool,abi:CAP_ABI,functionName,blockNumber:height})));
  const [maxDeposit,maxTotal,accountedBalance,depositsPaused,nextLeafIndex,asset,scope]=values;
  need(same(asset,p.asset)&&integer(scope)===p.scope,'TARGET_CAPACITY_POOL_MISMATCH');
  const after=await client.getBlock({blockNumber:height});
  need(integer(after.number)===height&&same(after.hash,expectedHash)&&await client.getChainId()===p.chainId,'TARGET_CAPACITY_SNAPSHOT_CHANGED');
  const snapshot={schema:'lincoln-target-capacity-snapshot/v1',chainId:p.chainId,pool:p.pool,asset:p.asset,blockNumber:String(height),blockHash:expectedHash,
    maxDeposit:String(integer(maxDeposit,UINT128,{positive:true})),maxTotal:String(integer(maxTotal,UINT128,{positive:true})),
    accountedBalance:String(integer(accountedBalance)),depositsPaused,nextLeafIndex:String(integer(nextLeafIndex)),treeDepth:p.treeDepth,
    canonicalBlockRechecked:true,runtimeCodeMatched:true,transactionsSent:false};
  normalizeSnapshot(snapshot);return snapshot;
}
