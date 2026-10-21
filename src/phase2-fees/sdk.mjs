// SPDX-License-Identifier: Apache-2.0
// Fee-route actions reuse the unchanged JoinSplit circuit and a distinct,
// proof-authenticated action envelope. Legacy zero-fee adapters stay separate.
import {encodeAbiParameters,keccak256,stringToHex} from 'viem';
import {
  normalizeProfile,normalizeSwapRoute,normalizeSwapAction,field,MAX_VALUE,NATIVE_ASSET,
  createDynamicReceive,createDynamicReceiver,prepareJoinSplit,joinSplitContext,
  joinSplitContextBase,publicTransaction,
} from '../phase2-asp/sdk.mjs';

export const FEE_SWAP_DOMAIN=keccak256(stringToHex('LINCOLN_PHASE2_FEE_ROUTES_V1'));
export const DEFAULT_SERVICE_FEE_BPS=20;
export const MAX_SERVICE_FEE_BPS=100;
export const FEE_ADAPTER_TYPES=Object.freeze(['Phase2FeeRouteAdapter','Phase2FeeRouter02Adapter']);
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const address=value=>{need(typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value)&&value.toLowerCase()!==NATIVE_ASSET,'INVALID_FEE_TREASURY');return value.toLowerCase();};

export function serviceFee(grossAmount,feeBps=DEFAULT_SERVICE_FEE_BPS){
  const gross=field(grossAmount,MAX_VALUE);
  need(Number.isSafeInteger(feeBps)&&feeBps>0&&feeBps<=MAX_SERVICE_FEE_BPS,'INVALID_SERVICE_FEE_BPS');
  return gross*BigInt(feeBps)/10000n;
}
export function minimumGrossOutput(minNetAmount,feeBps=DEFAULT_SERVICE_FEE_BPS){
  const net=field(minNetAmount,MAX_VALUE,true);
  need(Number.isSafeInteger(feeBps)&&feeBps>0&&feeBps<=MAX_SERVICE_FEE_BPS,'INVALID_SERVICE_FEE_BPS');
  const gross=(net-1n)*10000n/BigInt(10000-feeBps)+1n;
  need(gross<=MAX_VALUE,'GROSS_OUTPUT_EXCEEDS_UINT128');return gross;
}
export function normalizeFeeSwapRoute(options){
  const {route}=options;
  need(route&&FEE_ADAPTER_TYPES.includes(route.adapterType),'UNSUPPORTED_FEE_ADAPTER');
  const geometry=normalizeSwapRoute(options);
  need(route.adapterType!=='Phase2FeeRouter02Adapter'||geometry.protocol===0,'ROUTER02_REQUIRES_UNISWAP_V3');
  need(Number.isSafeInteger(route.feeBps),'INVALID_SERVICE_FEE_BPS');serviceFee(0n,route.feeBps);
  const treasury=address(route.treasury);
  need(![geometry.adapter,geometry.router,geometry.wrappedNative,geometry.factory,geometry.sourcePool,geometry.targetPool,...geometry.tokens].includes(treasury),'INVALID_FEE_TREASURY');
  return {...geometry,adapterType:route.adapterType,feeBps:route.feeBps,treasury};
}
export function normalizeFeeSwapAction(action){
  const keys=['processor','amountIn','minAmountOut','deadline','targetPrecommitment','encryptedTemplate','maxServiceFee'];
  need(action&&Object.getPrototypeOf(action)===Object.prototype&&Reflect.ownKeys(action).length===keys.length&&Reflect.ownKeys(action).every(k=>keys.includes(k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(action,k),'value')),'INVALID_FEE_SWAP_ACTION');
  const base=Object.fromEntries(keys.filter(k=>k!=='maxServiceFee').map(k=>[k,action[k]]));
  return {...normalizeSwapAction(base),maxServiceFee:field(action.maxServiceFee,MAX_VALUE)};
}
export function feeSwapActionHash({sourceProfile,targetProfile,route,action}){
  const r=normalizeFeeSwapRoute({sourceProfile,targetProfile,route}),a=normalizeFeeSwapAction(action);
  return keccak256(encodeAbiParameters([
    {type:'bytes32'},{type:'uint256'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},
    {type:'uint8'},{type:'bytes32'},{type:'uint16'},{type:'address'},{type:'address'},{type:'uint128'},{type:'uint128'},
    {type:'uint256'},{type:'uint256'},{type:'bytes32'},{type:'uint128'},
  ],[FEE_SWAP_DOMAIN,BigInt(r.chainId),r.adapter,r.sourcePool,r.targetPool,r.router,r.wrappedNative,r.factory,r.protocol,r.pathHash,
    r.feeBps,r.treasury,a.processor,a.amountIn,a.minAmountOut,a.deadline,a.targetPrecommitment,keccak256(a.encryptedTemplate),a.maxServiceFee]));
}
export function feeSwapActionEnvelope(options){return `${feeSwapActionHash(options)}${'00'.repeat(224)}`;}

/** minAmountOut is the user's NET private output after the service fee. */
export function prepareFeeSwap({account,sourceProfile,targetProfile,sourceState,route,action,inputs,receiver}){
  const r=normalizeFeeSwapRoute({sourceProfile,targetProfile,route});
  need(action&&typeof action==='object','INVALID_FEE_SWAP_ACTION');
  let selected={...action};
  if(selected.targetPrecommitment===undefined&&selected.encryptedTemplate===undefined){
    const invoice=receiver?.precommitment!==undefined?receiver:receiver?createDynamicReceiver(receiver,targetProfile):createDynamicReceive(account,targetProfile);
    selected={...selected,targetPrecommitment:invoice.precommitment,encryptedTemplate:invoice.encryptedTemplate};
  }
  const a=normalizeFeeSwapAction(selected);
  minimumGrossOutput(a.minAmountOut,r.feeBps);
  const prepared=prepareJoinSplit({account,profile:sourceProfile,state:sourceState,inputs,outputs:[],externalData:{
    recipient:r.adapter,feeRecipient:NATIVE_ASSET,processor:r.adapter,publicIn:0n,publicOut:a.amountIn,fee:0n,
  }});
  need(prepared.outputNotes[1].commitment===0n,'FEE_SWAP_REQUIRES_EMPTY_SECOND_OUTPUT');
  const options={sourceProfile,targetProfile,route,action:a},actionHash=feeSwapActionHash(options),actionEnvelope=feeSwapActionEnvelope(options);
  prepared.encryptedOutputs[1]=actionEnvelope;
  const context=joinSplitContext(sourceProfile,prepared.extData,prepared.encryptedOutputs,sourceState.asp);
  prepared.inputSignals.contextBase=joinSplitContextBase(sourceProfile,prepared.extData,prepared.encryptedOutputs);
  prepared.inputSignals.context=context;prepared.publicSignals[3]=String(context);
  return {...prepared,action:a,actionHash,actionEnvelope,route:r};
}
export function feeSwapTransaction(prepared,proof){
  need(prepared?.route&&FEE_ADAPTER_TYPES.includes(prepared.route.adapterType),'FEE_SWAP_PREPARATION_REQUIRED');
  const action=normalizeFeeSwapAction(prepared.action);
  return {...publicTransaction(prepared,proof),action:Object.fromEntries(Object.entries(action).map(([k,v])=>[k,typeof v==='bigint'?String(v):v]))};
}

// Profile validation remains the existing circuit/pool validation, not a claim
// that any new fee adapter has been deployed or independently reviewed.
export {normalizeProfile};
