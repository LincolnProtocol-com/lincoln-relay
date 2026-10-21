// SPDX-License-Identifier: Apache-2.0
// Fixed-source, read-only operating-fee valuation. Not a collateral/TVL oracle.
import {parseAbi,keccak256} from 'viem';

const SCHEMA='lincoln-mainnet-twap-prices/v1';
const GENESIS='0xaad15f3d702aaea00caf3e9bb56395efe9127bc3b31b24921abf1eee3409305c';
const FACTORY='0x1f7d7550b1b028f7571e69a784071f0205fd2efa',WETH='0x0bd7d308f8e1639fab988df18a8011f41eacad73';
const FACTORY_HASH='0xec72b1abd1f2faee020cfea9c646bd8994f9fb389054f6e574f103a895091739';
const WETH_HASH='0x5706be52f64875fee65a2cec0d80e47a23d8793cbe85d214b48445e2d05f5353';
const MAX128=(1n<<128n)-1n,MAX256=(1n<<256n)-1n,MAX160=(1n<<160n)-1n,Q192=1n<<192n,MAX_RATIO=10n**77n;
const MARKETS=[
  {id:'usdg',asset:'0x5fc5360d0400a0fd4f2af552add042d716f1d168',decimals:6,pool:'0x52e65b17fb6e5ba00ed806f37afcd2daa50271ca',fee:100,token0:WETH,
    poolHash:'0x3298b5dd4e6f115074c526a55ad05a36fd73a0034ac22ec6cbaab32cc9c1e8d2',assetHash:'0x864cc9ad53b338b82da1f7cab85ab0b3d5c8861acb422b6fec63cf36234f36a6',
    minNativeBalanceWei:'1000000000000000000000',minLiquidity:'1000000000000000000',minHarmonicLiquidity:'1000000000000000000'},
  {id:'pons',asset:'0x39dbed3a2bd333467115de45665cc57f813c4571',decimals:18,pool:'0xed50bdeea8adc232f159486192a4157281d722ff',fee:3000,token0:WETH,
    poolHash:'0x195c7d777448794bd8ebe573f2d4a4007abf142d9fcb895ef38603f4de8c2672',assetHash:'0x16c3d3ede897688ddff79262606f13bead398332e65001f192460fbac4e1fb85',
    minNativeBalanceWei:'25000000000000000000',minLiquidity:'20000000000000000000000',minHarmonicLiquidity:'20000000000000000000000'},
  {id:'cashcat',asset:'0x020bfc650a365f8bb26819deaabf3e21291018b4',decimals:18,pool:'0xd42a491087a15e5afd51feb3606066cc152d2b09',fee:3000,token0:'0x020bfc650a365f8bb26819deaabf3e21291018b4',
    poolHash:'0x4b535b6f1b07cd80f7c9a8259b0856d8d832896b7fd3b11e32b9f89dafe5a3cf',assetHash:'0x725781ccca82a0bf9b1f8920b2fe58ea1e4facf46d0db9f50226d6409de890fe',
    minNativeBalanceWei:'25000000000000000000',minLiquidity:'50000000000000000000000',minHarmonicLiquidity:'50000000000000000000000'},
];
const POOL_ABI=parseAbi(['function token0() view returns(address)','function token1() view returns(address)','function factory() view returns(address)','function fee() view returns(uint24)',
  'function liquidity() view returns(uint128)','function slot0() view returns(uint160,int24,uint16,uint16,uint16,uint8,bool)',
  'function observe(uint32[]) view returns(int56[],uint160[])']);
const FACTORY_ABI=parseAbi(['function getPool(address,address,uint24) view returns(address)']);
const TOKEN_ABI=parseAbi(['function decimals() view returns(uint8)','function balanceOf(address) view returns(uint256)']);
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
const clone=value=>structuredClone(value);
function object(value,allowed,required=[]){need(value&&Object.getPrototypeOf(value)===Object.prototype&&Reflect.ownKeys(value).every(key=>typeof key==='string'&&allowed.includes(key)
  &&Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value'))&&required.every(key=>Object.hasOwn(value,key)),'INVALID_TWAP_PRICE_POLICY');}
function number(value,min,max){need(Number.isSafeInteger(value)&&value>=min&&value<=max,'INVALID_TWAP_PRICE_POLICY');return value;}
function positive(value,max){need(typeof value==='string'&&/^[1-9][0-9]{0,77}$/.test(value)&&BigInt(value)<=max,'INVALID_TWAP_PRICE_POLICY');return value;}

/** Configuration cannot replace pool, factory, tokens, code pins or the RPC endpoint. */
export function normalizeTwapPricePolicy(input){
  object(input,['schema','id','windowSeconds','refreshSeconds','maxAgeSeconds','confirmationBlocks','maxSpotDeviationBps','haircutBps','markets'],['schema']);
  need(input.schema===SCHEMA,'INVALID_TWAP_PRICE_POLICY');
  const id=input.id??'eth-route-twap-30m-v1';need(typeof id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(id),'INVALID_TWAP_PRICE_POLICY');
  const windowSeconds=number(input.windowSeconds??1800,1800,7200),refreshSeconds=number(input.refreshSeconds??60,15,300),maxAgeSeconds=number(input.maxAgeSeconds??180,60,600);
  const confirmationBlocks=number(input.confirmationBlocks??30,30,1000),maxSpotDeviationBps=number(input.maxSpotDeviationBps??200,1,500),haircutBps=number(input.haircutBps??500,500,3000);
  need(maxAgeSeconds>=2*refreshSeconds,'INVALID_TWAP_PRICE_POLICY');
  const selected=input.markets??MARKETS.map(({id})=>({id}));need(Array.isArray(selected)&&selected.length===3,'INVALID_TWAP_PRICE_POLICY');
  const seen=new Set();for(const m of selected){object(m,['id','minNativeBalanceWei','minLiquidity','minHarmonicLiquidity'],['id']);need(MARKETS.some(p=>p.id===m.id)&&!seen.has(m.id),'INVALID_TWAP_PRICE_POLICY');seen.add(m.id);}
  const markets=MARKETS.map(defaults=>{const m=selected.find(p=>p.id===defaults.id);return{id:defaults.id,
    minNativeBalanceWei:positive(m.minNativeBalanceWei??defaults.minNativeBalanceWei,MAX256),minLiquidity:positive(m.minLiquidity??defaults.minLiquidity,MAX128),
    minHarmonicLiquidity:positive(m.minHarmonicLiquidity??defaults.minHarmonicLiquidity,MAX128)};});
  return{schema:SCHEMA,id,windowSeconds,refreshSeconds,maxAgeSeconds,confirmationBlocks,maxSpotDeviationBps,haircutBps,markets};
}

/*
 * getSqrtRatioAtTick below adapts the official Uniswap v3 SDK implementation
 * from JSBI to native BigInt (getSqrtRatioAtTick only):
 * https://github.com/Uniswap/v3-sdk/blob/main/src/utils/tickMath.ts
 * MIT License — Copyright (c) 2021 Uniswap Labs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
function getSqrtRatioAtTick(tick){
  need(Number.isSafeInteger(tick)&&tick>=-887272&&tick<=887272,'TWAP_TICK_INVALID');
  const abs=tick<0?-tick:tick;let ratio=abs&1?0xfffcb933bd6fad37aa2d162d1a594001n:1n<<128n;
  const multipliers=[0xfff97272373d413259a46990580e213an,0xfff2e50f5f656932ef12357cf3c7fdccn,0xffe5caca7e10e4e61c3624eaa0941cd0n,0xffcb9843d60f6159c9db58835c926644n,
    0xff973b41fa98c081472e6896dfb254c0n,0xff2ea16466c96a3843ec78b326b52861n,0xfe5dee046a99a2a811c461f1969c3053n,0xfcbe86c7900a88aedcffc83b479aa3a4n,
    0xf987a7253ac413176f2b074cf7815e54n,0xf3392b0822b70005940c7a398e4b70f3n,0xe7159475a2c29b7443b29c7fa6e889d9n,0xd097f3bdfd2022b8845ad8f792aa5825n,
    0xa9f746462d870fdf8a65dc1f90e061e5n,0x70d869a156d2a1b890bb3df62baf32f7n,0x31be135f97d08fd981231505542fcfa6n,0x9aa508b5b7a84e1c677de54f3e99bc9n,
    0x5d6af8dedb81196699c329225ee604n,0x2216e584f5fa1ea926041bedfe98n,0x48a170391f7dc42444e8fa2n];
  for(let i=0;i<multipliers.length;i++)if(abs&(1<<(i+1)))ratio=ratio*multipliers[i]>>128n;
  if(tick>0)ratio=MAX256/ratio;
  return(ratio>>32n)+(ratio% (1n<<32n)===0n?0n:1n);
}
function gcd(a,b){while(b)[a,b]=[b,a%b];return a;}
function rational(n,d){need(n>0n&&d>0n,'TWAP_PRICE_INVALID');const common=gcd(n,d);return{n:n/common,d:d/common};}
function min(a,b){return a.n*b.d<=b.n*a.d?a:b;}
function quoteRatio(sqrt,assetIsToken0){return assetIsToken0?rational((sqrt-1n)**2n,Q192):rational(Q192,sqrt**2n);}
function bigint(value,min,max){need(typeof value==='bigint'&&value>=min&&value<=max,'TWAP_OBSERVATION_INVALID');return value;}
function meanTick(observed,seconds){
  need(Array.isArray(observed)&&observed.length===2&&observed.every(a=>Array.isArray(a)&&a.length===2),'TWAP_OBSERVATION_INVALID');
  const ticks=observed[0].map(v=>bigint(v,-(1n<<55n),(1n<<55n)-1n)),spl=observed[1].map(v=>bigint(v,0n,MAX160));
  const delta=BigInt.asIntN(56,ticks[1]-ticks[0]),period=BigInt(seconds);let tick=delta/period;if(delta<0n&&delta%period!==0n)tick--;
  need(tick>=-887272n&&tick<887272n,'TWAP_TICK_INVALID');
  const liquidityDelta=BigInt.asUintN(160,spl[1]-spl[0]);need(liquidityDelta>0n,'TWAP_OBSERVATION_INVALID');
  const harmonic=period*MAX160/(liquidityDelta<<32n);need(harmonic>0n&&harmonic<=MAX128,'TWAP_OBSERVATION_INVALID');
  return{tick:Number(tick),harmonic};
}
function failureCode(error){
  if(typeof error?.code==='string'&&error.code.length<=80&&/^TWAP_[A-Z_]+$/.test(error.code))return error.code;
  let cause=error;for(let i=0;cause&&i<8;i++,cause=cause.cause)if(cause.name==='ContractFunctionRevertedError'||cause.code==='CALL_EXCEPTION')return'TWAP_OBSERVATION_UNAVAILABLE';
  return'TWAP_RPC_UNAVAILABLE';
}

/** A failed initial refresh returns an unavailable source, so signed jobs can recover. */
export async function createTwapPriceSource({client,policy,now=Date.now}={}){
  const normalized=normalizeTwapPricePolicy(policy);need(client&&typeof now==='function','INVALID_TWAP_PRICE_SOURCE');
  const clock=()=>{const t=now();need(Number.isSafeInteger(t)&&t>=0,'INVALID_TWAP_PRICE_CLOCK');return t;};
  let stored=null,inflight=null,timer=null,closed=false,closing=null,invalidated=false,lastError=null,lastAttemptAt=null,lastSuccessAt=null;
  function freshPrices(){return closed||invalidated?[]:(stored?.prices??[]).filter(p=>Date.parse(p.expiresAt)>clock());}
  function status(){const prices=freshPrices(),available=prices.length===MARKETS.length;return{enabled:true,available,state:closed?'closed':available?'ready':prices.length?'partial':stored?.prices.length&&!invalidated?'stale':'unavailable',refreshing:inflight!==null,
    unavailableReason:available?null:closed?'TWAP_PRICE_SOURCE_CLOSED':invalidated?lastError??'TWAP_PRICES_UNAVAILABLE':prices.length?'TWAP_PRICES_PARTIAL':stored?.prices.length?'TWAP_PRICES_STALE':lastError??'TWAP_PRICES_UNAVAILABLE',
    availableAssets:prices.map(p=>p.asset),perAssetErrors:clone(stored?.perAssetErrors??{}),lastError,lastAttemptAt,lastSuccessAt,policy:clone(normalized),snapshot:stored?clone(stored.metadata):null};}
  function snapshot(){need(!closed,'TWAP_PRICE_SOURCE_CLOSED');need(!invalidated&&stored!==null,'TWAP_PRICES_UNAVAILABLE');const prices=freshPrices();need(prices.length>0,stored.prices.length?'TWAP_PRICES_STALE':'TWAP_PRICES_UNAVAILABLE');return clone(prices);}
  async function collect(){
    need(await client.getChainId()===4663,'TWAP_WRONG_CHAIN');
    need(same((await client.getBlock({blockNumber:0n})).hash,GENESIS),'TWAP_GENESIS_MISMATCH');
    const head=await client.getBlockNumber({cacheTime:0});need(typeof head==='bigint'&&head>BigInt(normalized.confirmationBlocks),'TWAP_HEAD_INVALID');
    const height=head-BigInt(normalized.confirmationBlocks),block=await client.getBlock({blockNumber:height});
    need(typeof block.hash==='string'&&/^0x[0-9a-f]{64}$/i.test(block.hash)&&typeof block.timestamp==='bigint'&&block.timestamp>0n&&block.timestamp<=BigInt(Math.floor(Number.MAX_SAFE_INTEGER/1000)),'TWAP_BLOCK_INVALID');
    const observedAt=Number(block.timestamp)*1000,expiresAt=observedAt+normalized.maxAgeSeconds*1000;
    need(observedAt<=clock()+30000&&expiresAt>clock(),'TWAP_BLOCK_STALE');
    if(stored&&!invalidated){
      need(height>=BigInt(stored.metadata.blockNumber),'TWAP_BLOCK_REGRESSION');
      need(height!==BigInt(stored.metadata.blockNumber)||same(block.hash,stored.metadata.blockHash),'TWAP_CANONICAL_BLOCK_CHANGED');
      // A market may retain a previous snapshot after transport failure. Even
      // when the head advances, its original anchor must still be canonical.
      const freshAssets=new Set(stored.prices.filter(p=>Date.parse(p.expiresAt)>clock()).map(p=>p.asset));
      const anchors=new Map(stored.metadata.markets.filter(m=>freshAssets.has(m.asset)).map(m=>[`${m.blockNumber}:${m.blockHash}`,m]));
      need(anchors.size<=MARKETS.length,'TWAP_CANONICAL_BLOCK_CHANGED');
      for(const anchor of anchors.values()){
        const anchorHeight=BigInt(anchor.blockNumber),canonical=anchorHeight===height?block:await client.getBlock({blockNumber:anchorHeight});
        need(same(canonical.hash,anchor.blockHash),'TWAP_CANONICAL_BLOCK_CHANGED');
      }
    }
    const read=(address,abi,functionName,args=[])=>client.readContract({address,abi,functionName,args,blockNumber:height});
    async function code(address,expected){const runtime=await client.getCode({address,blockNumber:height});need(typeof runtime==='string'&&/^0x[0-9a-f]+$/i.test(runtime)&&runtime!=='0x'&&same(keccak256(runtime),expected),'TWAP_CODE_MISMATCH');}
    await Promise.all([code(FACTORY,FACTORY_HASH),code(WETH,WETH_HASH)]);
    need(await read(WETH,TOKEN_ABI,'decimals')===18,'TWAP_TOKEN_DECIMALS_MISMATCH');
    const prices=[],markets=[],failures={};
    for(const m of MARKETS){
      try{
      const floor=normalized.markets.find(p=>p.id===m.id),token1=same(m.token0,WETH)?m.asset:WETH;
      const [token0Actual,token1Actual,factoryActual,fee,liquidity,slot0,registered,decimals,nativeBalance,observed]=await Promise.all([
        read(m.pool,POOL_ABI,'token0'),read(m.pool,POOL_ABI,'token1'),read(m.pool,POOL_ABI,'factory'),read(m.pool,POOL_ABI,'fee'),read(m.pool,POOL_ABI,'liquidity'),read(m.pool,POOL_ABI,'slot0'),
        read(FACTORY,FACTORY_ABI,'getPool',[m.asset,WETH,m.fee]),read(m.asset,TOKEN_ABI,'decimals'),read(WETH,TOKEN_ABI,'balanceOf',[m.pool]),read(m.pool,POOL_ABI,'observe',[[normalized.windowSeconds,0]]),
        code(m.pool,m.poolHash),code(m.asset,m.assetHash)]);
      need(same(token0Actual,m.token0)&&same(token1Actual,token1)&&same(factoryActual,FACTORY)&&same(registered,m.pool)&&fee===m.fee,'TWAP_MARKET_BINDING_MISMATCH');
      need(decimals===m.decimals,'TWAP_TOKEN_DECIMALS_MISMATCH');
      bigint(liquidity,1n,MAX128);bigint(nativeBalance,0n,MAX256);
      need(liquidity>=BigInt(floor.minLiquidity)&&nativeBalance>=BigInt(floor.minNativeBalanceWei),'TWAP_LIQUIDITY_BELOW_MINIMUM');
      need(Array.isArray(slot0)&&slot0.length===7&&typeof slot0[0]==='bigint'&&slot0[0]>1n&&slot0[0]<(1n<<160n)&&Number.isSafeInteger(slot0[1])&&slot0[1]>=-887272&&slot0[1]<=887272
        &&Number.isSafeInteger(slot0[3])&&slot0[3]>=2&&slot0[6]===true,'TWAP_MARKET_UNAVAILABLE');
      const {tick,harmonic}=meanTick(observed,normalized.windowSeconds);need(harmonic>=BigInt(floor.minHarmonicLiquidity),'TWAP_LIQUIDITY_BELOW_MINIMUM');
      const reference=getSqrtRatioAtTick(tick),spotSquared=slot0[0]**2n,referenceSquared=reference**2n;
      const smaller=spotSquared<referenceSquared?spotSquared:referenceSquared,larger=spotSquared>referenceSquared?spotSquared:referenceSquared;
      need((larger-smaller)*10000n<=smaller*BigInt(normalized.maxSpotDeviationBps),'TWAP_SPOT_DEVIATION');
      const assetIsToken0=same(m.asset,m.token0),conservativeBoundary=getSqrtRatioAtTick(assetIsToken0?tick:tick+1);
      const beforeDiscount=min(quoteRatio(conservativeBoundary,assetIsToken0),quoteRatio(slot0[0],assetIsToken0));
      const price=rational(beforeDiscount.n*BigInt(1000000-m.fee)*BigInt(10000-normalized.haircutBps),beforeDiscount.d*1000000n*10000n);
      need(price.n<=MAX_RATIO&&price.d<=MAX_RATIO,'TWAP_PRICE_RATIO_LIMIT');
      const source=`uniswap-v3-twap:${m.id};pool=${m.pool};block=${height}:${block.hash};window=${normalized.windowSeconds};venueFeePips=${m.fee};haircutBps=${normalized.haircutBps}`;
      need(source.length<=512,'TWAP_PRICE_INVALID');
      prices.push({asset:m.asset,decimals:m.decimals,weiPerBaseUnitNumerator:String(price.n),weiPerBaseUnitDenominator:String(price.d),
        observedAt:new Date(observedAt).toISOString(),expiresAt:new Date(expiresAt).toISOString(),source});
      markets.push({id:m.id,pool:m.pool,asset:m.asset,decimals:m.decimals,fee:m.fee,blockNumber:String(height),blockHash:block.hash,observedAt:new Date(observedAt).toISOString(),expiresAt:new Date(expiresAt).toISOString(),
        meanTick:tick,spotTick:slot0[1],liquidity:String(liquidity),harmonicMeanLiquidity:String(harmonic),nativeBalanceWei:String(nativeBalance),
        spotDeviationBpsCeiling:String(((larger-smaller)*10000n+smaller-1n)/smaller)});
      }catch(error){failures[m.id]={asset:m.asset,code:failureCode(error),at:new Date(clock()).toISOString()};}
    }
    need(same((await client.getBlock({blockNumber:height})).hash,block.hash),'TWAP_CANONICAL_BLOCK_CHANGED');
    need(await client.getChainId()===4663,'TWAP_WRONG_CHAIN');need(expiresAt>clock(),'TWAP_BLOCK_STALE');
    return{prices,failures,metadata:{blockNumber:String(height),blockHash:block.hash,observedAt:new Date(observedAt).toISOString(),expiresAt:new Date(expiresAt).toISOString(),canonicalBlockRechecked:true,markets}};
  }
  function refresh(){
    if(closed)return Promise.reject(Object.assign(new Error('TWAP_PRICE_SOURCE_CLOSED'),{code:'TWAP_PRICE_SOURCE_CLOSED'}));
    if(inflight)return inflight;lastAttemptAt=new Date(clock()).toISOString();
    inflight=collect().then(next=>{if(!closed){
      const previous=invalidated?null:stored,prices=[],markets=[];
      for(const m of MARKETS){const current=next.prices.find(p=>p.asset===m.asset),error=next.failures[m.id];
        const retained=!current&&error?.code==='TWAP_RPC_UNAVAILABLE'?previous?.prices.find(p=>p.asset===m.asset):null;
        if(current||retained){prices.push(current??retained);const metadata=current?next.metadata.markets.find(p=>p.id===m.id):previous?.metadata.markets.find(p=>p.id===m.id);if(metadata)markets.push({...metadata,retainedAfterTransportFailure:!current});}
      }
      stored={prices,perAssetErrors:next.failures,metadata:{...next.metadata,markets}};invalidated=false;
      lastError=Object.values(next.failures)[0]?.code??null;if(next.prices.length)lastSuccessAt=new Date(clock()).toISOString();
    }return status();}).catch(error=>{
      const code=failureCode(error);lastError=code;if(code!=='TWAP_RPC_UNAVAILABLE')invalidated=true;
      throw Object.assign(new Error(code),{code});
    }).finally(()=>{inflight=null;});return inflight;
  }
  await refresh().catch(()=>{});
  timer=setInterval(()=>{void refresh().catch(()=>{});},normalized.refreshSeconds*1000);timer.unref?.();
  return{snapshot,status,refresh,close(){if(closing)return closing;closed=true;clearInterval(timer);closing=Promise.resolve(inflight).catch(()=>{}).then(()=>{});return closing;}};
}
