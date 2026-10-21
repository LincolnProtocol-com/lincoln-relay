// SPDX-License-Identifier: Apache-2.0
// Pure public quotes for the optional official relayer; no RPC, signing or price feed.
export const DEFAULT_SERVICE_FEE_BPS=30;
export const LEGACY_SERVICE_FEE_BPS=20;
export const SERVICE_FEE_POLICY_V1='lincoln-service-fees/v1';
export const SERVICE_FEE_POLICY_V2='lincoln-service-fees/v2';
export const MAINNET_FEE_TREASURY='0x9cf17a6e3c75d200f58283a165c442a8a3994555';
export const DEFAULT_ETH_GAS_FEE_UNITS='20000000000000';
export const MAX_ETH_GAS_FEE_UNITS='200000000000000';
const MAX_BPS=100,MAX128=(1n<<128n)-1n;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const units=value=>{need(typeof value==='bigint'||typeof value==='string'&&/^(0|[1-9][0-9]{0,38})$/.test(value),'INVALID_SERVICE_FEE_UNITS');const n=BigInt(value);need(n>=0n&&n<=MAX128,'INVALID_SERVICE_FEE_UNITS');return n;};
function object(value,keys){
  need(value&&Object.getPrototypeOf(value)===Object.prototype
    &&Reflect.ownKeys(value).every(k=>keys.includes(k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')),'INVALID_SERVICE_FEE_POLICY');
}
function bps(value,{zero=true}={}){
  need(Number.isSafeInteger(value)&&value>=(zero?0:1)&&value<=MAX_BPS,'INVALID_SERVICE_FEE_BPS');return value;
}
const address=value=>{need(typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value)&&!/^0x0{40}$/i.test(value),'INVALID_FEE_TREASURY');return value.toLowerCase();};
function identity(value){need(typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(value),'INVALID_SERVICE_FEE_POLICY_ID');return value;}
function operation(value,{free=false}={}){
  object(value,['bps','includesGas']);bps(value.bps);need(typeof value.includesGas==='boolean','INVALID_SERVICE_FEE_POLICY');
  if(free)need(value.bps===0&&value.includesGas===false,'SERVICE_FEE_FREE_OPERATION_REQUIRED');
  return Object.freeze({bps:value.bps,includesGas:value.includesGas});
}

/** Omitted schema remains v1: existing testnet records are never reinterpreted. */
export function normalizeServiceFeePolicy(input={}){
  object(input,['schema','id','serviceFeeBps','gasFeeUnits','transferServiceFeeUnits','feeAsset',
    'withdrawal','holderExit','ragequit','privateTransfer','swap','deposit']);
  if(input.schema===undefined||input.schema===SERVICE_FEE_POLICY_V1){
    object(input,['schema','id','serviceFeeBps','gasFeeUnits','transferServiceFeeUnits']);
    const serviceFeeBps=bps(input.serviceFeeBps??LEGACY_SERVICE_FEE_BPS,{zero:false});
    return Object.freeze({schema:SERVICE_FEE_POLICY_V1,id:identity(input.id??'launch-20bps-v1'),serviceFeeBps,
      gasFeeUnits:String(units(input.gasFeeUnits??'0')),transferServiceFeeUnits:String(units(input.transferServiceFeeUnits??'0'))});
  }
  need(input.schema===SERVICE_FEE_POLICY_V2,'INVALID_SERVICE_FEE_POLICY');
  object(input,['schema','id','feeAsset','gasFeeUnits','withdrawal','holderExit','ragequit','privateTransfer','swap','deposit']);
  need(input.feeAsset==='current-pool-asset','INVALID_SERVICE_FEE_ASSET');
  // Explicit per-pool gas quotes avoid silently applying ETH wei to ERC20 pools.
  need(input.gasFeeUnits!==undefined,'SERVICE_FEE_GAS_QUOTE_REQUIRED');
  const withdrawal=operation(input.withdrawal),holderExit=operation(input.holderExit),ragequit=operation(input.ragequit,{free:true});
  const deposit=operation(input.deposit??{bps:0,includesGas:false},{free:true});
  object(input.privateTransfer,['fixedUnits','includesGas']);
  need(typeof input.privateTransfer.includesGas==='boolean','INVALID_SERVICE_FEE_POLICY');
  const privateTransfer=Object.freeze({fixedUnits:String(units(input.privateTransfer.fixedUnits)),includesGas:input.privateTransfer.includesGas});
  object(input.swap,['bps','treasury','immutable','includesGas']);bps(input.swap.bps,{zero:false});
  need(input.swap.immutable===true&&(input.swap.includesGas===undefined||input.swap.includesGas===false),'INVALID_SWAP_FEE_POLICY');
  const swap=Object.freeze({bps:input.swap.bps,treasury:address(input.swap.treasury),immutable:true,includesGas:false});
  return Object.freeze({schema:SERVICE_FEE_POLICY_V2,id:identity(input.id),feeAsset:'current-pool-asset',gasFeeUnits:String(units(input.gasFeeUnits)),
    withdrawal,holderExit,ragequit,privateTransfer,swap,deposit});
}

/** Launch presets require an explicit asset name. Other assets require a priced,
 * operator-approved quote in that asset's units; this module cannot convert ETH.
 */
export function createLaunchServiceFeePolicy({asset,gasFeeUnits,id='mainnet-launch-30bps-v2'}={}){
  need(typeof asset==='string'&&/^[A-Z][A-Z0-9]{0,31}$/.test(asset),'SERVICE_FEE_ASSET_REQUIRED');
  if(asset==='ETH'){
    gasFeeUnits??=DEFAULT_ETH_GAS_FEE_UNITS;
    need(units(gasFeeUnits)<=BigInt(MAX_ETH_GAS_FEE_UNITS),'SERVICE_FEE_GAS_QUOTE_ABOVE_ETH_CAP');
  }else need(gasFeeUnits!==undefined,'SERVICE_FEE_GAS_QUOTE_REQUIRED');
  return normalizeServiceFeePolicy({schema:SERVICE_FEE_POLICY_V2,id,feeAsset:'current-pool-asset',gasFeeUnits,
    withdrawal:{bps:30,includesGas:true},holderExit:{bps:30,includesGas:true},ragequit:{bps:0,includesGas:false},
    privateTransfer:{fixedUnits:'0',includesGas:false},deposit:{bps:0,includesGas:false},
    swap:{bps:30,treasury:MAINNET_FEE_TREASURY,immutable:true,includesGas:false}});
}

export function quoteServiceFee({policy,kind,grossAmount='0'}={}){
  const p=normalizeServiceFeePolicy(policy),gross=units(grossAmount),v2=p.schema===SERVICE_FEE_POLICY_V2;
  need(['withdrawal','private-transfer','holder-exit','ragequit','deposit',...(v2?['swap']:[])].includes(kind),'INVALID_SERVICE_FEE_KIND');
  let percentage=0n,fixed=0n,gas=0n,rate=0;
  const output=kind==='withdrawal'||kind==='holder-exit'||kind==='swap';
  if(v2){
    const key={'holder-exit':'holderExit','private-transfer':'privateTransfer'}[kind]??kind,op=p[key];
    if(output)need(gross>0n,'INVALID_SERVICE_FEE_AMOUNT');
    if(kind==='private-transfer')need(gross===0n,'PRIVATE_PAYMENT_AMOUNT_NOT_REQUIRED');
    rate=op.bps??0;percentage=gross*BigInt(rate)/10000n;fixed=BigInt(op.fixedUnits??0);gas=op.includesGas?BigInt(p.gasFeeUnits):0n;
  }else if(kind==='withdrawal'){
    need(gross>0n,'INVALID_SERVICE_FEE_AMOUNT');rate=p.serviceFeeBps;percentage=gross*BigInt(rate)/10000n;gas=BigInt(p.gasFeeUnits);
  }else if(kind==='private-transfer'){
    need(gross===0n,'PRIVATE_PAYMENT_AMOUNT_NOT_REQUIRED');fixed=BigInt(p.transferServiceFeeUnits);gas=BigInt(p.gasFeeUnits);
  }else if(kind==='holder-exit'){
    need(gross>0n,'INVALID_SERVICE_FEE_AMOUNT');gas=BigInt(p.gasFeeUnits);
  }else need(gross===0n,'INVALID_SERVICE_FEE_AMOUNT');
  const totalFee=percentage+fixed+gas;need(totalFee<=MAX128,'SERVICE_FEE_OVERFLOW');
  if(output)need(totalFee<gross,'SERVICE_FEE_EXCEEDS_OUTPUT');
  return {schema:v2?'lincoln-service-fee-quote/v2':'lincoln-service-fee-quote/v1',policyId:p.id,kind,serviceFeeBps:rate,
    grossAmount:String(gross),percentageServiceFee:String(percentage),fixedServiceFee:String(fixed),quotedGasFee:String(gas),
    totalFee:String(totalFee),netRecipientAmount:output?String(gross-totalFee):null,
    feeAsset:kind==='swap'?'swap-output-asset':'current-pool-asset',gasQuoteKind:'operator-configured-fixed-asset-units',
    protocolFeeMandatory:false,transactionsSent:false};
}

/** Validate only NEW jobs. Already proved/signed/recovering jobs retain their
 * original proof-bound fee; a later policy never reprices them.
 */
export function validateCommercialFee(intent,policy){
  if(policy===null||policy===undefined)return;
  const p=normalizeServiceFeePolicy(policy),v2=p.schema===SERVICE_FEE_POLICY_V2;
  if(intent.kind==='swap'){
    const route=intent.routeEntry?.route;
    need(['Phase2FeeRouteAdapter','Phase2FeeRouter02Adapter'].includes(route?.adapterType),'PAID_SWAP_ADAPTER_REQUIRED');
    need(route.feeBps===(v2?p.swap.bps:p.serviceFeeBps),'SWAP_SERVICE_FEE_POLICY_MISMATCH');
    if(v2)need(address(route.treasury)===p.swap.treasury,'SWAP_SERVICE_FEE_TREASURY_MISMATCH');
    return;
  }
  const fee=units(intent.extData.fee),gross=units(intent.extData.publicOut??intent.signals?.[2]??'0');
  const kind=intent.kind==='ragequit'?'ragequit':intent.kind==='holderExit'?'holder-exit':intent.kind==='deposit'?'deposit':gross===fee?'private-transfer':'withdrawal';
  const quote=quoteServiceFee({policy:p,kind,grossAmount:['private-transfer','ragequit','deposit'].includes(kind)?'0':String(gross)});
  need(fee===BigInt(quote.totalFee),'SERVICE_FEE_QUOTE_MISMATCH');
}
