// SPDX-License-Identifier: Apache-2.0
// Public, proof-bound fee offers. No note witnesses or wallet signing occurs here.
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {openServiceStore} from '../phase1-service/store.mjs';
import {normalizeServiceFeePolicy,quoteServiceFee} from '../phase2-fees/policy.mjs';
import {quoteMainnetGasPrice,quoteMainnetGasPriceDetails} from './signer.mjs';
import {normalizeTwapPricePolicy} from './twap-prices.mjs';

const SCHEMA='lincoln-relay-gas-pricing/v1',QUOTE_SCHEMA='lincoln-service-fee-quote/v3';
const NATIVE='0x'+'0'.repeat(40),MAX128=(1n<<128n)-1n,MAX_GAS=5000000n,MAX_PRICE=100000000n,MAX_QUOTES=1024;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const clone=value=>structuredClone(value);
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hex64=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const jobId=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(value);
function object(value,allowed,required=allowed){
  need(value&&Object.getPrototypeOf(value)===Object.prototype&&Reflect.ownKeys(value).every(k=>typeof k==='string'&&allowed.includes(k)
    &&Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value'))&&required.every(k=>Object.hasOwn(value,k)),'INVALID_GAS_PRICING_POLICY');
}
function units(value,{zero=false,max=MAX128,code='INVALID_GAS_PRICING_UNITS'}={}){
  need(typeof value==='bigint'||typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value),code);
  const n=BigInt(value);need(n>=(zero?0n:1n)&&n<=max,code);return n;
}
function address(value){need(typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value),'INVALID_GAS_PRICING_ASSET');return value.toLowerCase();}
function timestamp(value){const t=typeof value==='string'?Date.parse(value):NaN;need(Number.isSafeInteger(t)&&new Date(t).toISOString()===value,'INVALID_GAS_PRICE_TIMESTAMP');return t;}
const ceil=(n,d)=>(n+d-1n)/d;
const count=value=>{need(Number.isSafeInteger(value)&&value>=0&&value<=2,'FEE_QUOTE_SHAPE_MISMATCH');return value;};

/** Pure normalization. Freshness is checked at runtime, never inferred from disk. */
export function normalizeGasPricingPolicy(input){
  object(input,['schema','id','quoteTTLSeconds','maxGasPriceWei','maxGasUnits','gasBufferBps','gasModels','assetPrices','priceFeed','billingGasPrice','executionGasBufferBps'],
    ['schema','maxGasPriceWei','maxGasUnits','gasModels']);
  need(input.schema===SCHEMA,'INVALID_GAS_PRICING_POLICY');
  const id=input.id??'bounded-relay-gas-v1',quoteTTLSeconds=input.quoteTTLSeconds??120,gasBufferBps=input.gasBufferBps??2000;
  need(typeof id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(id),'INVALID_GAS_PRICING_POLICY');
  need(Number.isSafeInteger(quoteTTLSeconds)&&quoteTTLSeconds>=1&&quoteTTLSeconds<=600
    &&Number.isSafeInteger(gasBufferBps)&&gasBufferBps>=0&&gasBufferBps<=10000,'INVALID_GAS_PRICING_POLICY');
  const maxGasUnits=units(input.maxGasUnits,{max:MAX_GAS}),maxGasPriceWei=units(input.maxGasPriceWei,{max:MAX_PRICE});
  object(input.gasModels,['withdrawal','private-transfer','holder-exit','swap']);
  const gasModels={};
  for(const kind of ['withdrawal','private-transfer']){
    object(input.gasModels[kind],['0','1','2']);gasModels[kind]={};
    for(const shape of ['0','1','2'])gasModels[kind][shape]=String(units(input.gasModels[kind][shape],{max:maxGasUnits}));
  }
  for(const kind of ['holder-exit','swap'])gasModels[kind]=String(units(input.gasModels[kind],{max:maxGasUnits}));
  need(Array.isArray(input.assetPrices??[])&&(input.assetPrices??[]).length<=64,'INVALID_GAS_PRICING_POLICY');
  const seen=new Set(),assetPrices=(input.assetPrices??[]).map(p=>{
    object(p,['asset','decimals','weiPerBaseUnitNumerator','weiPerBaseUnitDenominator','observedAt','expiresAt','source']);
    const asset=address(p.asset);need(asset!==NATIVE&&!seen.has(asset),'INVALID_GAS_PRICING_ASSET');seen.add(asset);
    need(Number.isSafeInteger(p.decimals)&&p.decimals>=0&&p.decimals<=36,'INVALID_GAS_PRICING_DECIMALS');
    const observed=timestamp(p.observedAt),expires=timestamp(p.expiresAt);
    need(expires>observed&&expires-observed<=86400000,'INVALID_GAS_PRICE_TIMESTAMP');
    need(typeof p.source==='string'&&p.source.length>0&&p.source.length<=512&&!/[\x00-\x1f\x7f]/.test(p.source),'INVALID_GAS_PRICE_SOURCE');
    return{asset,decimals:p.decimals,weiPerBaseUnitNumerator:String(units(p.weiPerBaseUnitNumerator,{max:10n**77n})),
      weiPerBaseUnitDenominator:String(units(p.weiPerBaseUnitDenominator,{max:10n**77n})),observedAt:p.observedAt,expiresAt:p.expiresAt,source:p.source};
  });
  const normalized={schema:SCHEMA,id,quoteTTLSeconds,maxGasPriceWei:String(maxGasPriceWei),maxGasUnits:String(maxGasUnits),gasBufferBps,gasModels,assetPrices};
  // Omission stays omission: legacy policy snapshots keep their original hashes.
  if(input.priceFeed!==undefined)normalized.priceFeed=normalizeTwapPricePolicy(input.priceFeed);
  if(input.billingGasPrice!==undefined||input.executionGasBufferBps!==undefined){
    const billing=input.billingGasPrice,execution=input.executionGasBufferBps;
    object(billing,['schema','multiplierBps','minimumAdditionWei']);
    need(billing.schema==='lincoln-base-fee-billing/v1'&&Number.isSafeInteger(billing.multiplierBps)
      &&billing.multiplierBps>=10000&&billing.multiplierBps<=12500
      &&Number.isSafeInteger(execution)&&execution>=gasBufferBps&&execution<=10000,'INVALID_GAS_PRICING_POLICY');
    const addition=units(billing.minimumAdditionWei,{zero:true,max:maxGasPriceWei<5000000n?maxGasPriceWei:5000000n});
    normalized.billingGasPrice={schema:billing.schema,multiplierBps:billing.multiplierBps,minimumAdditionWei:String(addition)};
    normalized.executionGasBufferBps=execution;
  }
  for(const model of Object.values(gasModels))for(const raw of typeof model==='string'?[model]:Object.values(model)){
    padded(normalized,raw,maxGasUnits);
    if(normalized.billingGasPrice)padded(normalized,raw,maxGasUnits,normalized.executionGasBufferBps);
  }
  return normalized;
}

function priceFor(policy,asset,at,{decimals}={}){
  asset=address(asset);if(asset===NATIVE){need(decimals===undefined||decimals===18,'GAS_ASSET_DECIMALS_MISMATCH');return{numerator:1n,denominator:1n,expires:Infinity};}
  const p=policy.assetPrices.find(p=>p.asset===asset);need(p,'GAS_ASSET_PRICE_MISSING');
  need(decimals===undefined||p.decimals===decimals,'GAS_ASSET_DECIMALS_MISMATCH');
  need(timestamp(p.observedAt)<=at+30000&&timestamp(p.expiresAt)>at,'GAS_ASSET_PRICE_STALE');
  return{numerator:BigInt(p.weiPerBaseUnitNumerator),denominator:BigInt(p.weiPerBaseUnitDenominator),expires:timestamp(p.expiresAt)};
}
function padded(policy,raw,maxGas,buffer=policy.gasBufferBps){
  const n=units(raw,{max:BigInt(policy.maxGasUnits)}),gas=ceil(n*BigInt(10000+buffer),10000n);
  need(gas<=BigInt(policy.maxGasUnits)&&gas<=maxGas,'FEE_QUOTE_GAS_LIMIT');return gas;
}
function billingPrices(policy,base){
  const cap=BigInt(policy.maxGasPriceWei);base=units(base,{zero:true,max:cap});
  const b=policy.billingGasPrice,multiplied=ceil(base*BigInt(b.multiplierBps),10000n),added=base+BigInt(b.minimumAdditionWei);
  const candidate=multiplied>added?multiplied:added,execution=base*2n>base+20000000n?base*2n:base+20000000n;
  return{base,billing:candidate>cap?cap:candidate,execution:execution>cap?cap:execution};
}
function rawModel(policy,kind,outputCount){
  need(['withdrawal','private-transfer','holder-exit'].includes(kind),'FEE_QUOTE_KIND_UNSUPPORTED');
  count(outputCount);need(kind!=='holder-exit'||outputCount===0,'FEE_QUOTE_SHAPE_MISMATCH');
  return BigInt(kind==='holder-exit'?policy.gasModels[kind]:policy.gasModels[kind][String(outputCount)]);
}
function compensated(policy){need(policy.schema==='lincoln-service-fees/v2'&&policy.withdrawal.includesGas===true
  &&policy.holderExit.includesGas===true&&policy.privateTransfer.includesGas===true,'DYNAMIC_GAS_COMPENSATION_REQUIRED');return policy;}
function quoteFields({profile,feePolicy,policy,quoteId,kind,gross,outputCount,raw,gas,price,issuedAt,baseFeePerGas}){
  const asset=address(profile.pool.asset),valuation=priceFor(policy,asset,issuedAt,{decimals:profile.asset.decimals}),cost=gas*price;
  const converted=ceil(cost*valuation.denominator,valuation.numerator);need(converted<=MAX128,'FEE_QUOTE_AMOUNT_OVERFLOW');
  const fee=quoteServiceFee({policy:{...feePolicy,gasFeeUnits:String(converted)},kind,grossAmount:String(gross)});
  const expiresAt=Math.min(issuedAt+policy.quoteTTLSeconds*1000,valuation.expires);
  need(expiresAt>issuedAt,'GAS_ASSET_PRICE_STALE');
  const fields={...fee,schema:QUOTE_SCHEMA,quoteId,chainId:4663,pool:address(profile.pool.address),asset,assetDecimals:profile.asset.decimals,
    processor:address(profile.relayer),outputCount,rawGasUnits:String(raw),gasUnits:String(gas),gasPriceWei:String(price),gasCostWei:String(cost),
    gasFee:fee.quotedGasFee,issuedAt:new Date(issuedAt).toISOString(),expiresAt:new Date(expiresAt).toISOString(),
    gasPricingPolicyId:policy.id,gasPricingPolicySHA256:sha(policy),serviceFeePolicySHA256:sha(feePolicy),
    gasQuoteKind:'operator-bounded-execution-ceiling-in-current-pool-asset',actualGasRefund:false};
  if(policy.billingGasPrice){
    const prices=billingPrices(policy,baseFeePerGas);
    need(price===prices.billing,'FEE_QUOTE_STORE_CORRUPT');
    fields.gasQuoteKind='operator-base-fee-budget-in-current-pool-asset';
    fields.billingGasPriceWei=String(prices.billing);
    fields.executionGasUnits=String(padded(policy,raw,MAX_GAS,policy.executionGasBufferBps));
    fields.executionGasPriceWei=String(prices.execution);
    fields.baseFeePerGas=String(prices.base);
  }
  return fields;
}

/** Durable offers survive restart and fee-policy updates. Bound offers are never pruned. */
export async function createFeeQuoteBook({client,profile,serviceFeePolicy,policy,directory,maxGas=MAX_GAS,now=Date.now,assetPriceLoader,feeRecipients=[]}={}){
  const pricing=normalizeGasPricingPolicy(policy),feePolicy=compensated(normalizeServiceFeePolicy(serviceFeePolicy));
  need(profile?.chain?.id===4663&&typeof directory==='string'&&directory.length>0&&typeof now==='function','INVALID_FEE_QUOTE_BOOK');
  need(assetPriceLoader===undefined||typeof assetPriceLoader==='function','INVALID_FEE_QUOTE_BOOK');
  need(!pricing.priceFeed||typeof assetPriceLoader==='function','GAS_PRICE_FEED_LOADER_REQUIRED');
  need(Array.isArray(feeRecipients),'INVALID_FEE_QUOTE_BOOK');const payees=new Set(feeRecipients.map(a=>address(a).toLowerCase()));
  profile=clone(profile);address(profile.pool.address);address(profile.pool.asset);need(address(profile.relayer)!==NATIVE,'INVALID_FEE_QUOTE_PROCESSOR');
  need(Number.isSafeInteger(profile.asset?.decimals)&&profile.asset.decimals>=0&&profile.asset.decimals<=36,'INVALID_GAS_PRICING_DECIMALS');
  need(address(profile.pool.asset)!==NATIVE||profile.asset.decimals===18,'GAS_ASSET_DECIMALS_MISMATCH');
  maxGas=units(maxGas,{max:MAX_GAS});
  for(const model of Object.values(pricing.gasModels))for(const raw of typeof model==='string'?[model]:Object.values(model)){
    padded(pricing,raw,maxGas);
    if(pricing.billingGasPrice)padded(pricing,raw,maxGas,pricing.executionGasBufferBps);
  }
  const clock=()=>{const t=now();need(Number.isSafeInteger(t)&&t>=0,'INVALID_FEE_QUOTE_CLOCK');return t;};
  // Price expiry must not prevent startup and reconciliation of signed jobs.
  // Public price formatting is normalized above; known source metadata stays exact.
  const sourcePrice=!pricing.priceFeed&&pricing.assetPrices.find(p=>p.asset===address(profile.pool.asset));
  need(!sourcePrice||sourcePrice.decimals===profile.asset.decimals,'GAS_ASSET_DECIMALS_MISMATCH');
  const identity='lincoln-mainnet-fee-quotes:'+sha({chainId:4663,pool:address(profile.pool.address),asset:address(profile.pool.asset),
    decimals:profile.asset.decimals,processor:address(profile.relayer)});
  const store=await openServiceStore({directory:path.join(directory,'fee-quotes'),identity,filename:'quotes.json'});
  let state,tail=Promise.resolve(),closing=false;
  const validateRecord=record=>{
    object(record,['quote','serviceFeePolicy','gasPricingPolicy','fingerprint','boundJobId','digest']);
    need(record.fingerprint===null&&record.boundJobId===null||hex64(record.fingerprint)&&jobId(record.boundJobId),'FEE_QUOTE_STORE_CORRUPT');
    const {digest,...body}=record;need(hex64(digest)&&sha(body)===digest,'FEE_QUOTE_STORE_CORRUPT');
    const p=normalizeGasPricingPolicy(record.gasPricingPolicy),f=compensated(normalizeServiceFeePolicy(record.serviceFeePolicy)),q=record.quote;
    need(q&&hex64(q.quoteId)&&q.schema===QUOTE_SCHEMA,'FEE_QUOTE_STORE_CORRUPT');
    const issuedAt=timestamp(q.issuedAt),raw=units(q.rawGasUnits,{max:BigInt(p.maxGasUnits)}),model=rawModel(p,q.kind,q.outputCount);
    need(raw>=model,'FEE_QUOTE_STORE_CORRUPT');const gas=padded(p,raw,MAX_GAS),price=units(q.gasPriceWei,{zero:!!p.billingGasPrice,max:BigInt(p.maxGasPriceWei)});
    const gross=units(q.grossAmount,{zero:q.kind==='private-transfer'});need(q.kind!=='private-transfer'||gross===0n,'FEE_QUOTE_STORE_CORRUPT');
    const expected=quoteFields({profile,feePolicy:f,policy:p,quoteId:q.quoteId,kind:q.kind,gross,outputCount:q.outputCount,raw,gas,price,issuedAt,
      ...(p.billingGasPrice?{baseFeePerGas:q.baseFeePerGas}:{})});
    need(isDeepStrictEqual(expected,q),'FEE_QUOTE_STORE_CORRUPT');return record;
  };
  try{
    state=await store.read()??{schema:'lincoln-mainnet-fee-quotes/v1',identity,records:[]};
    object(state,['schema','identity','records']);need(state.schema==='lincoln-mainnet-fee-quotes/v1'&&state.identity===identity
      &&Array.isArray(state.records)&&state.records.length<=MAX_QUOTES,'FEE_QUOTE_STORE_CORRUPT');
    const ids=new Set();for(const r of state.records){validateRecord(r);need(!ids.has(r.quote.quoteId),'FEE_QUOTE_STORE_CORRUPT');ids.add(r.quote.quoteId);}
  }catch(error){await store.close();throw error;}
  const serial=fn=>{need(!closing,'FEE_QUOTE_BOOK_CLOSED');const run=tail.then(fn);tail=run.catch(()=>{});return run;};
  const save=async records=>{const next={schema:state.schema,identity,records};await store.write(next);state=next;};
  const find=id=>{need(hex64(id),'FEE_QUOTE_UNKNOWN');const r=state.records.find(r=>r.quote.quoteId===id);need(r,'FEE_QUOTE_UNKNOWN');return r;};
  function currentPricing(asset){
    if(!pricing.priceFeed)return pricing;
    const snapshot=()=>{
      let prices;try{prices=assetPriceLoader();}catch{need(false,'GAS_PRICE_FEED_UNAVAILABLE');}
      try{need(Array.isArray(prices),'GAS_PRICE_FEED_INVALID');return normalizeGasPricingPolicy({...pricing,assetPrices:prices});}
      catch{need(false,'GAS_PRICE_FEED_INVALID');}
    };
    // ETH is exactly 1:1 and needs no external valuation. A failed source can
    // never introduce a token fallback; native quotes simply save no prices.
    if(address(asset)===NATIVE){try{return snapshot();}catch{return{...pricing,assetPrices:[]};}}
    return snapshot();
  }
  const valueInWei=(asset,value,{decimals}={})=>{need(!closing,'FEE_QUOTE_BOOK_CLOSED');const p=priceFor(currentPricing(asset),asset,clock(),{decimals});return units(value,{zero:true})*p.numerator/p.denominator;};
  const availability=()=>{try{priceFor(currentPricing(profile.pool.asset),profile.pool.asset,clock(),{decimals:profile.asset.decimals});return{available:true,unavailableReason:null};}
    catch(error){if(['GAS_ASSET_PRICE_MISSING','GAS_ASSET_PRICE_STALE','GAS_ASSET_DECIMALS_MISMATCH','GAS_PRICE_FEED_UNAVAILABLE','GAS_PRICE_FEED_INVALID'].includes(error.code))return{available:false,unavailableReason:error.code};throw error;}};
  async function gasQuote(raw){
    if(!pricing.billingGasPrice){
      const gas=padded(pricing,raw,maxGas),price=await quoteMainnetGasPrice({client,maxFeePerGasWei:pricing.maxGasPriceWei});
      return{gasUnits:String(gas),gasPriceWei:String(price),costWei:String(gas*price)};
    }
    const gas=padded(pricing,raw,maxGas,pricing.executionGasBufferBps),details=await quoteMainnetGasPriceDetails({client,maxFeePerGasWei:pricing.maxGasPriceWei});
    const prices=billingPrices(pricing,details.baseFeePerGas);
    return{gasUnits:String(gas),gasPriceWei:String(details.gasPriceWei),costWei:String(gas*details.gasPriceWei),
      baseFeePerGas:String(prices.base),billingGasPriceWei:String(prices.billing)};
  }
  return{
    publicConfig(){return{enabled:true,...availability(),requestSchema:'lincoln-fee-request/v3',quoteSchema:QUOTE_SCHEMA,...clone(pricing),maximumStoredQuotes:MAX_QUOTES,
      quoteBinding:'one-job-id-and-transaction-fingerprint',actualGasRefund:false};},
    capacity(){
      need(!closing,'FEE_QUOTE_BOOK_CLOSED');const at=clock();let bound=0,liveUnbound=0,expiredUnbound=0;
      for(const record of state.records){
        if(record.fingerprint!==null)bound++;
        else if(timestamp(record.quote.expiresAt)>at)liveUnbound++;
        else expiredUnbound++;
      }
      // This is capacity after the next quote's existing expiry pruning. Merely
      // observing readiness never writes, and bound recovery history is retained.
      const canIssue=bound+liveUnbound<MAX_QUOTES;
      return{total:state.records.length,liveUnbound,expiredUnbound,bound,max:MAX_QUOTES,canIssue,reason:canIssue?null:'FEE_QUOTE_CAPACITY'};
    },
    async quote(request){return serial(async()=>{
      object(request,['schema','kind','grossAmount','outputCount','gasUnits'],['schema','kind','grossAmount','outputCount']);
      need(request.schema==='lincoln-fee-request/v3','INVALID_FEE_QUOTE_REQUEST');
      const model=rawModel(pricing,request.kind,request.outputCount),raw=request.gasUnits===undefined?model:units(request.gasUnits,{max:BigInt(pricing.maxGasUnits)});
      need(raw>=model,'FEE_QUOTE_GAS_BELOW_MODEL');const gross=units(request.grossAmount,{zero:request.kind==='private-transfer'});
      need(request.kind!=='private-transfer'||gross===0n,'PRIVATE_PAYMENT_AMOUNT_NOT_REQUIRED');
      const quotePricing=currentPricing(profile.pool.asset);
      priceFor(quotePricing,profile.pool.asset,clock(),{decimals:profile.asset.decimals});
      const records=state.records.filter(r=>r.fingerprint!==null||timestamp(r.quote.expiresAt)>clock());need(records.length<MAX_QUOTES,'FEE_QUOTE_CAPACITY');
      const quoted=await gasQuote(raw),issuedAt=clock(),quoteId=randomBytes(32).toString('hex');
      const quote=quoteFields({profile,feePolicy,policy:quotePricing,quoteId,kind:request.kind,gross,outputCount:request.outputCount,raw,
        gas:pricing.billingGasPrice?padded(pricing,raw,maxGas):BigInt(quoted.gasUnits),
        price:BigInt(quoted.billingGasPriceWei??quoted.gasPriceWei),issuedAt,
        ...(pricing.billingGasPrice?{baseFeePerGas:quoted.baseFeePerGas}:{})});
      const record={quote,serviceFeePolicy:clone(feePolicy),gasPricingPolicy:clone(quotePricing),fingerprint:null,boundJobId:null};
      await save([...records,{...record,digest:sha(record)}]);return clone(quote);
    });},
    validate(intent,quoteId,{allowExpired=false}={}){
      need(!closing,'FEE_QUOTE_BOOK_CLOSED');const r=find(quoteId),q=r.quote;
      need(typeof allowExpired==='boolean','INVALID_FEE_QUOTE_REQUEST');
      if(timestamp(q.expiresAt)<=clock())need(allowExpired&&r.fingerprint!==null&&r.fingerprint===intent.fingerprint&&r.boundJobId===intent.id,'FEE_QUOTE_EXPIRED');
      need(!r.fingerprint||r.fingerprint===intent.fingerprint&&r.boundJobId===intent.id,'FEE_QUOTE_REPLAY');
      need(intent?.extData&&Array.isArray(intent.signals)&&intent.to?.toLowerCase()===q.pool,'FEE_QUOTE_BINDING_MISMATCH');
      const data=intent.extData,fee=units(data.fee,{zero:true}),gross=intent.kind==='holderExit'?units(intent.signals[2]):units(data.publicOut,{zero:true});
      const kind=intent.kind==='holderExit'?'holder-exit':intent.kind==='transact'?(gross===fee?'private-transfer':'withdrawal'):null;
      const outputs=kind==='holder-exit'?0:intent.signals.slice(7,9).filter(s=>BigInt(s)!==0n).length;
      need(kind===q.kind&&outputs===q.outputCount,'FEE_QUOTE_SHAPE_MISMATCH');
      need(String(kind==='private-transfer'?0n:gross)===q.grossAmount&&fee===BigInt(q.totalFee),'FEE_QUOTE_FEE_MISMATCH');
      const payee=data.feeRecipient?.toLowerCase();
      need(data.processor?.toLowerCase()===q.processor&&(fee===0n||payee===q.processor||payees.has(payee)),'FEE_QUOTE_RECIPIENT_MISMATCH');
      return clone(q);
    },
    checkCost({quote,gas,gasPriceWei,estimatedGasUnits,baseFeePerGas}){
      need(!closing,'FEE_QUOTE_BOOK_CLOSED');const record=find(quote?.quoteId),stored=record.quote;
      need(isDeepStrictEqual(quote,stored),'FEE_QUOTE_BINDING_MISMATCH');
      if(record.gasPricingPolicy.billingGasPrice){
        need(estimatedGasUnits!==undefined&&baseFeePerGas!==undefined,'FEE_QUOTE_COST_INPUT_REQUIRED');
        const estimated=units(estimatedGasUnits,{max:maxGas}),base=units(baseFeePerGas,{zero:true,max:MAX_PRICE});
        need(units(gas,{max:maxGas})<=BigInt(stored.executionGasUnits)
          &&units(gasPriceWei,{max:MAX_PRICE})<=BigInt(stored.executionGasPriceWei)
          &&base<=BigInt(stored.executionGasPriceWei)&&estimated*base<=BigInt(stored.gasCostWei),'FEE_QUOTE_COST_EXCEEDED');
      }else need(units(gas,{max:maxGas})<=BigInt(stored.gasUnits)&&units(gasPriceWei,{max:MAX_PRICE})<=BigInt(stored.gasPriceWei),'FEE_QUOTE_COST_EXCEEDED');
      return clone(stored);
    },
    async bind(quoteId,fingerprint,boundJobId){return serial(async()=>{
      need(hex64(fingerprint)&&jobId(boundJobId),'INVALID_FEE_QUOTE_FINGERPRINT');const r=find(quoteId);
      need(r.fingerprint===null||r.fingerprint===fingerprint&&r.boundJobId===boundJobId,'FEE_QUOTE_REPLAY');
      if(r.fingerprint!==null)return clone(r.quote);need(timestamp(r.quote.expiresAt)>clock(),'FEE_QUOTE_EXPIRED');
      const body={quote:r.quote,serviceFeePolicy:r.serviceFeePolicy,gasPricingPolicy:r.gasPricingPolicy,fingerprint,boundJobId};
      await save(state.records.map(record=>record===r?{...body,digest:sha(body)}:record));return clone(r.quote);
    });},
    async quoteGas({rawGas}={}){need(!closing,'FEE_QUOTE_BOOK_CLOSED');const model=BigInt(pricing.gasModels.swap),raw=rawGas===undefined?model:units(rawGas,{max:BigInt(pricing.maxGasUnits)});
      return gasQuote(raw>model?raw:model);},
    valueInWei,
    assertCoveredByAsset({asset,units:value,gas,gasPriceWei,decimals}){
      const g=units(gas,{max:maxGas}),p=units(gasPriceWei,{max:BigInt(pricing.maxGasPriceWei)}),cost=g*p,fee=valueInWei(asset,value,{decimals});
      need(fee>=cost,'GAS_FEE_VALUE_INSUFFICIENT');return{covered:true,feeValueWei:String(fee),costWei:String(cost)};
    },
    async close(){if(closing)return;closing=true;await tail;await store.close();},
  };
}
