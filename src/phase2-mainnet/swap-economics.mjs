// SPDX-License-Identifier: Apache-2.0
// Relayer admission policy only. Immutable adapters still pay their output fee
// to the Safe; this module neither adds a source-pool gas fee nor changes a proof.
import {netPhase2Quote} from '../phase2-aggregator/amounts.mjs';
import {MAINNET_FEE_TREASURY} from '../phase2-fees/policy.mjs';

const MAX128=(1n<<128n)-1n,MAX256=(1n<<256n)-1n,BPS=10000n,RATE=30n;
const PAID_TYPES=new Set(['Phase2FeeRouteAdapter','Phase2FeeRouter02Adapter','Phase2FeeHedgeFunV4Adapter']);
const INVALID='SWAP_ECONOMICS_INVALID_INPUT',UNSUPPORTED='SWAP_ECONOMICS_UNSUPPORTED_ROUTE';
export class SwapEconomicError extends Error {
  constructor(code){super(code);this.name='SwapEconomicError';this.code=code;}
}
const need=(ok,code=INVALID)=>{if(!ok)throw new SwapEconomicError(code);};
const plain=value=>value!==null&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype;
function field(value,key,{optional=false}={}){
  need(plain(value));const descriptor=Object.getOwnPropertyDescriptor(value,key);
  if(descriptor===undefined&&optional)return undefined;
  need(descriptor!==undefined&&Object.hasOwn(descriptor,'value'));return descriptor.value;
}
function uint(value,{maximum=MAX128,positive=false}={}){
  need(typeof value==='bigint'||typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value)
    ||typeof value==='number'&&Number.isSafeInteger(value));
  const n=BigInt(value);need(n>=0n&&n<=maximum&&(!positive||n>0n));return n;
}
function address(value){need(typeof value==='string'&&/^0x[0-9a-f]{40}$/i.test(value));return value.toLowerCase();}
function routeIdentity(entry){
  const route=field(entry,'route'),targetProfile=field(entry,'targetProfile'),pool=field(targetProfile,'pool');
  const id=field(entry,'id');need(typeof id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(id));
  const adapterType=field(route,'adapterType');need(PAID_TYPES.has(adapterType),UNSUPPORTED);
  need(field(route,'feeBps')===Number(RATE),UNSUPPORTED);
  need(field(route,'executionEnabled',{optional:true})!==false,UNSUPPORTED);
  const adapter=address(field(route,'adapter')),treasury=address(field(route,'treasury'));
  need(treasury===MAINNET_FEE_TREASURY,UNSUPPORTED);
  const targetAsset=address(field(pool,'asset')),targetPool=address(field(pool,'address'));
  const assetMetadata=field(targetProfile,'asset'),targetDecimals=field(assetMetadata,'decimals');
  need(Number.isSafeInteger(targetDecimals)&&targetDecimals>=0&&targetDecimals<=36);
  const declaredTarget=field(route,'targetPool',{optional:true});
  if(declaredTarget!==undefined)need(address(declaredTarget)===targetPool);
  const declaredId=field(route,'id',{optional:true});if(declaredId!==undefined)need(declaredId===id);
  return {id,route,adapter,adapterType,treasury,targetAsset,targetPool,targetDecimals};
}

function guaranteedFee(minNet,maxFee){
  const net=uint(minNet,{positive:true}),cap=uint(maxFee);
  // Use the adapter's exact inverse, then its floored fee. floor(net*30/9970)
  // can overstate guaranteed revenue: net=333 is met by gross=333 with fee=0.
  const minGross=(net-1n)*BPS/(BPS-RATE)+1n;need(minGross<=MAX128);
  const fee=minGross*RATE/BPS;need(cap>=fee);
  return {net,cap,minGross,fee};
}

function quoteAmounts(quote,identity){
  need(field(quote,'routeId')===identity.id&&field(quote,'adapterType')===identity.adapterType);
  need(address(field(quote,'adapter'))===identity.adapter&&address(field(quote,'treasury'))===identity.treasury);
  need(address(field(quote,'targetAsset'))===identity.targetAsset&&address(field(quote,'targetPool'))===identity.targetPool);
  need(field(quote,'serviceFeeBps')===Number(RATE));
  const sourcePool=field(identity.route,'sourcePool',{optional:true});
  if(sourcePool!==undefined)need(address(field(quote,'sourcePool'))===address(sourcePool));
  const net=field(quote,'netQuote'),gross=uint(field(quote,'amountOut'),{positive:true}),slippage=field(quote,'slippageBPS');
  need(Number.isSafeInteger(slippage)&&slippage>=1&&slippage<=500);
  let expected;
  try{expected=netPhase2Quote({grossAmountOut:gross,serviceFeeBps:Number(RATE),slippageBPS:slippage});}
  catch{throw new SwapEconomicError(INVALID);}
  for(const key of ['grossAmountOut','serviceFeeAmount','netAmountOut','minNetOut','minGrossOut','maxServiceFee']){
    need(uint(field(net,key))===expected[key]);
  }
  need(field(net,'serviceFeeBps')===Number(RATE)&&field(net,'slippageBPS')===slippage);
  return guaranteedFee(expected.minNetOut,expected.maxServiceFee);
}

function optionalGas(quote){
  const raw=field(quote,'gasEstimate',{optional:true});
  if(raw===undefined||raw===null)return undefined;
  if(!(typeof raw==='bigint'||typeof raw==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(raw)
    ||typeof raw==='number'&&Number.isSafeInteger(raw)))return undefined;
  const n=BigInt(raw);return n>0n&&n<=MAX256?n:undefined;
}

/** feeQuotes supplies a swap-model floor and gas padding in quoteGas(), and
 * fresh operator-approved asset conversion in assertCoveredByAsset(). Its
 * missing/stale-price failures deliberately propagate; they are not subsidies.
 * quote.gasEstimate is only DEX gas and may increase, never replace, that floor.
 */
export function createSwapEconomicGuard({feeQuotes}={}){
  need(feeQuotes&&['quoteGas','valueInWei','assertCoveredByAsset'].every(key=>typeof feeQuotes[key]==='function'));
  async function covered(identity,minimum,{gas,gasPriceWei,costWei,stage}){
    gas=uint(gas,{maximum:MAX256,positive:true});gasPriceWei=uint(gasPriceWei,{maximum:MAX256,positive:true});
    const cost=gas*gasPriceWei;need(cost<=MAX256);
    if(costWei!==undefined)need(uint(costWei,{maximum:MAX256,positive:true})===cost);
    const feeValue=uint(await feeQuotes.valueInWei(identity.targetAsset,minimum.fee,{decimals:identity.targetDecimals}),{maximum:MAX256});
    let coverage;
    try{coverage=await feeQuotes.assertCoveredByAsset({asset:identity.targetAsset,units:minimum.fee,gas,gasPriceWei,decimals:identity.targetDecimals});}
    catch(error){if(error?.code==='GAS_FEE_VALUE_INSUFFICIENT'||error?.message==='GAS_FEE_VALUE_INSUFFICIENT'){
      throw new SwapEconomicError('SWAP_BELOW_MINIMUM_ECONOMIC_AMOUNT');
    }throw error;}
    need(coverage?.covered===true&&feeValue>=cost,'SWAP_BELOW_MINIMUM_ECONOMIC_AMOUNT');
    need(uint(coverage.feeValueWei,{maximum:MAX256})===feeValue&&uint(coverage.costWei,{maximum:MAX256})===cost);
    return {schema:'lincoln-swap-gas-economics/v1',stage,routeId:identity.id,outputAsset:identity.targetAsset,
      immutableServiceFeeBps:Number(RATE),minimumNetOutputUnits:String(minimum.net),minimumGrossOutputUnits:String(minimum.minGross),
      minimumGuaranteedServiceFeeUnits:String(minimum.fee),maximumServiceFeeUnits:String(minimum.cap),
      minimumServiceFeeValueWei:String(feeValue),gasUnits:String(gas),gasPriceWei:String(gasPriceWei),gasCostCeilingWei:String(cost),
      minimumRevenueLessGasWei:String(feeValue-cost),covered:true,revenueRecipient:identity.treasury,
      separateGasFeeAdded:false,gasCostKind:stage==='quote'?'buffered-complete-swap-model-floor':'padded-complete-call-estimate',
      valuation:'fresh-operator-approved-asset-price',profitExcludes:['ASP publishing','infrastructure','asset conversion costs','execution failure costs']};
  }
  return Object.freeze({
    async quote({quote,entry}={}){
      const identity=routeIdentity(entry),minimum=quoteAmounts(quote,identity);
      const gasQuote=await feeQuotes.quoteGas({rawGas:optionalGas(quote)});
      const gasEconomics=await covered(identity,minimum,{gas:gasQuote.gasUnits,gasPriceWei:gasQuote.gasPriceWei,costWei:gasQuote.costWei,stage:'quote'});
      return {...quote,gasEconomics};
    },
    async submission({intent,gas,gasPriceWei}={}){
      need(field(intent,'kind')==='swap');const identity=routeIdentity(field(intent,'routeEntry'));
      need(field(intent,'routeId')===identity.id&&address(field(intent,'to'))===identity.adapter);
      const args=field(intent,'args');need(Array.isArray(args)&&args.length>0);
      const action=args[0],minimum=guaranteedFee(field(action,'minAmountOut'),field(action,'maxServiceFee'));
      // The caller already padded the COMPLETE proof/adapter estimate and chose
      // its actual signer gas price. Do not pad again or trust a previous quote.
      return covered(identity,minimum,{gas,gasPriceWei,stage:'submission'});
    },
  });
}
