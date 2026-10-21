// SPDX-License-Identifier: Apache-2.0
// Pinned, read-only exact-input quotes. Values, route and timing are public.
// The self-deployed Uniswap development pools do not represent market prices.
import { isAddress, keccak256, parseAbi } from 'viem';
import { normalizeProfile, normalizeSwapRoute, MAX_VALUE, NOTE_MODEL, profileReleaseFlags } from './sdk.mjs';
import {FEE_ADAPTER_TYPES,normalizeFeeSwapRoute} from '../phase2-fees/sdk.mjs';
import {netPhase2Quote} from '../phase2-aggregator/amounts.mjs';
import {readTargetCapacitySnapshot,assertQuotedTargetCapacity} from '../phase2-mainnet/target-capacity.mjs';

const MAX_UINT256=(1n<<256n)-1n;
const ZERO='0x0000000000000000000000000000000000000000';
export class Phase2RouteQuoteError extends Error {
  constructor(code){super(code);this.name='Phase2RouteQuoteError';this.code=code;}
}
function must(value,code){if(!value)throw new Phase2RouteQuoteError(code);}
function same(a,b){return typeof a==='string' && typeof b==='string' && a.toLowerCase()===b.toLowerCase();}
function address(value){must(isAddress(value) && !same(value,ZERO),'INVALID_QUOTE_ADDRESS');return value.toLowerCase();}
function hash(value){must(typeof value==='string' && /^0x[0-9a-f]{64}$/i.test(value) && !/^0x0{64}$/i.test(value),'INVALID_QUOTE_HASH');return value.toLowerCase();}
function integer(value,max=MAX_UINT256,nonzero=false){
  must(typeof value==='bigint' || typeof value==='number' && Number.isSafeInteger(value) || typeof value==='string' && /^(0|[1-9][0-9]*)$/.test(value),'INVALID_QUOTE_INTEGER');
  const n=BigInt(value);must(n>=0n && n<=max && (!nonzero||n>0n),'INVALID_QUOTE_INTEGER');return n;
}
const PRIVACY_POOL_ABI=parseAbi(['function ASSET() view returns(address)','function SCOPE() view returns(uint256)','function VERIFIER() view returns(address)','function HOLDER_EXIT_VERIFIER() view returns(address)','function ASP_REGISTRY() view returns(address)']);
const REGISTRY_ABI=parseAbi(['function PROVIDER() view returns(address)']);
const PERIPHERY_ABI=parseAbi(['function factory() view returns(address)','function WETH9() view returns(address)']);
const ADAPTER_ABI=parseAbi([
  'function SOURCE_POOL() view returns(address)','function TARGET_POOL() view returns(address)','function ROUTER() view returns(address)',
  'function WRAPPED_NATIVE() view returns(address)','function FACTORY() view returns(address)','function PROTOCOL() view returns(uint8)',
  'function TOKEN_IN() view returns(address)','function TOKEN_OUT() view returns(address)','function SOURCE_ASSET() view returns(address)',
  'function TARGET_ASSET() view returns(address)','function SOURCE_NATIVE() view returns(bool)','function TARGET_NATIVE() view returns(bool)',
  'function HOPS() view returns(uint256)','function PATH_HASH() view returns(bytes32)','function PATH() view returns(bytes)',
  'function routeTokens() view returns(address[])','function hopPools() view returns(address[])',
  'function FEE_BPS() view returns(uint16)','function TREASURY() view returns(address)',
]);
const DEX_POOL_ABI=parseAbi(['function token0() view returns(address)','function token1() view returns(address)','function factory() view returns(address)',
  'function fee() view returns(uint24)','function tickSpacing() view returns(int24)','function liquidity() view returns(uint128)']);
const FACTORY_ABIS=[parseAbi(['function getPool(address,address,uint24) view returns(address)']),parseAbi(['function getPool(address,address,int24) view returns(address)'])];
const QUOTER_ABI=parseAbi(['function quoteExactInput(bytes path,uint256 amountIn) returns(uint256 amountOut,uint160[] sqrtPriceX96AfterList,uint32[] initializedTicksCrossedList,uint256 gasEstimate)']);

function endpoint(profile) {
  let p;
  try {
    p=normalizeProfile(profile);
  } catch {throw new Phase2RouteQuoteError('INVALID_QUOTE_PROFILE');}
  return {...p,genesisHash:hash(profile.genesisHash),runtimeCodeHash:hash(profile.pool?.runtimeCodeHash),
    verifier:address(profile.verifier?.address),verifierCodeHash:hash(profile.verifier?.runtimeCodeHash),
    exitVerifier:address(profile.exitVerifier?.address),exitVerifierCodeHash:hash(profile.exitVerifier?.runtimeCodeHash),
    registryCodeHash:hash(profile.registry?.runtimeCodeHash),noteModel:NOTE_MODEL};
}
function capture(sourceProfile,targetProfile,route) {
  must(route?.executionEnabled===undefined||route.executionEnabled===true,'QUOTE_ROUTE_DISABLED');
  must(route?.targetCapacityRequired===undefined||typeof route.targetCapacityRequired==='boolean','INVALID_TARGET_CAPACITY_POLICY');
  const source=endpoint(sourceProfile),target=endpoint(targetProfile,{target:true});
  must(source.chainId===target.chainId && source.genesisHash===target.genesisHash,'QUOTE_POOL_NETWORK_MISMATCH');
  let geometry;
  const paid=FEE_ADAPTER_TYPES.includes(route?.adapterType);
  try {geometry=(paid?normalizeFeeSwapRoute:normalizeSwapRoute)({sourceProfile,targetProfile,route});}
  catch {throw new Phase2RouteQuoteError('INVALID_QUOTE_ROUTE');}
  must(typeof route.id==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(route.id),'INVALID_ROUTE_ID');
  must(['Phase2RouteAdapter','Phase2Router02Adapter',...FEE_ADAPTER_TYPES].includes(route.adapterType),'INVALID_ROUTE_ADAPTER_TYPE');
  must(!['Phase2Router02Adapter','Phase2FeeRouter02Adapter'].includes(route.adapterType)||geometry.protocol===0,'INVALID_ROUTER02_PROTOCOL');
  const quoter=address(route.quoter);
  must(![geometry.adapter,geometry.router,geometry.wrappedNative,geometry.factory].includes(quoter),'DUPLICATE_ROUTE_ROLE');
  const hashes=Object.fromEntries(['adapter','router','factory','wrappedNative','quoter'].map(role=>[role,hash(route.runtimeCodeHashes?.[role])]));
  must(Array.isArray(route.hops) && route.hops.length===geometry.hops,'INVALID_ROUTE_HOPS');
  const hops=route.hops.map((hop,i)=>{
    const parameter=Number(integer(hop.parameter,geometry.protocol===0?999999n:0x7fffffn,true));
    must(parameter===geometry.parameters[i] && address(hop.tokenIn)===geometry.tokens[i] && address(hop.tokenOut)===geometry.tokens[i+1],'ROUTE_HOP_PATH_MISMATCH');
    return {pool:address(hop.pool),parameter,tokenIn:geometry.tokens[i],tokenOut:geometry.tokens[i+1],runtimeCodeHash:hash(hop.runtimeCodeHash)};
  });
  must(new Set(hops.map(h=>h.pool)).size===hops.length,'REPEATED_ROUTE_POOL');
  const mainnetFork=typeof route.deployment==='string'&&route.deployment.includes('mainnet')&&route.deployment.includes('fork');
  return {...geometry,id:route.id,paid,adapterType:route.adapterType,quoter,hashes,hops,source,target,targetProfile:structuredClone(targetProfile),targetCapacityRequired:route.targetCapacityRequired===true,deployment:route.deployment??'unspecified-test-deployment',
    priceContext:mainnetFork?'Official mainnet DEX state copied into a local fork; this quote is not a public mainnet execution guarantee.':geometry.protocol===0?'Self-deployed development pools; quoted base units are not a market price.':'Public testnet liquidity quote; not a production execution guarantee.'};
}
async function bounded(items,task) {
  const result=new Array(items.length);let cursor=0,failed=false,failure;
  await Promise.all(Array.from({length:Math.min(4,items.length)},async()=>{
    while(!failed && cursor<items.length){const i=cursor++;try{result[i]=await task(items[i],i);}catch(error){if(!failed){failed=true;failure=error;}}}
  }));
  if(failed)throw failure;return result;
}
async function blockAt(client,blockNumber) {
  const block=await client.getBlock({blockNumber});
  must(integer(block?.number)===blockNumber,'QUOTE_BLOCK_NUMBER_MISMATCH');
  return {number:blockNumber,hash:hash(block.hash),timestamp:integer(block.timestamp)};
}

/** Does not sign, approve, broadcast, hold wallet keys, or generate a proof. */
export async function quotePhase2Route({client,sourceProfile,targetProfile,route,amountIn,slippageBPS=100,deadlineSeconds=600,blockNumber:requestedBlock}={}) {
  const capturedSource=structuredClone(sourceProfile),r=capture(capturedSource,structuredClone(targetProfile),structuredClone(route)),releaseFlags=profileReleaseFlags(capturedSource);
  must(typeof amountIn==='bigint' && amountIn>0n && amountIn<=MAX_VALUE,'INVALID_QUOTE_INPUT');
  must(Number.isSafeInteger(slippageBPS) && slippageBPS>=1 && slippageBPS<=500,'INVALID_QUOTE_SLIPPAGE');
  must(Number.isSafeInteger(deadlineSeconds) && deadlineSeconds>=1 && deadlineSeconds<=3600,'INVALID_QUOTE_DEADLINE');
  for(const method of ['getChainId','getBlockNumber','getBlock','getCode','readContract','simulateContract'])must(typeof client?.[method]==='function','INVALID_QUOTE_CLIENT');
  must(await client.getChainId()===r.chainId,'QUOTE_CHAIN_MISMATCH');
  const head=integer(await client.getBlockNumber({cacheTime:0})),blockNumber=requestedBlock===undefined?head:integer(requestedBlock);
  must(blockNumber<=head,'QUOTE_BLOCK_AFTER_HEAD');
  const block=await blockAt(client,blockNumber),genesis=await blockAt(client,0n);
  must(genesis.hash===r.source.genesisHash,'QUOTE_GENESIS_MISMATCH');
  const pins=[...Object.entries(r.hashes).map(([role,pin])=>({address:r[role],pin})),
    ...[r.source,r.target].flatMap(p=>[{address:p.pool,pin:p.runtimeCodeHash},{address:p.verifier,pin:p.verifierCodeHash},
      {address:p.exitVerifier,pin:p.exitVerifierCodeHash},{address:p.registry,pin:p.registryCodeHash}]),
    ...r.hops.map(h=>({address:h.pool,pin:h.runtimeCodeHash}))];
  const unique=new Map();
  for(const pin of pins){must(!unique.has(pin.address)||unique.get(pin.address)===pin.pin,'CONFLICTING_ROUTE_CODE_PINS');unique.set(pin.address,pin.pin);}
  const codeTasks=[...unique].map(([address,pin])=>({address,pin}));
  for(const token of r.tokens)if(!unique.has(token))codeTasks.push({address:token,pin:null});
  await bounded(codeTasks,async target=>{
    const code=await client.getCode({address:target.address,blockNumber});
    must(typeof code==='string' && /^0x(?:[0-9a-f]{2})+$/i.test(code),'ROUTE_TOKEN_CODE_MISSING');
    if(target.pin)must(keccak256(code)===target.pin,'ROUTE_CODE_HASH_MISMATCH');
  });
  const specs=[];
  const add=(key,address,abi,functionName,args)=>specs.push({key,address,abi,functionName,...(args===undefined?{}:{args})});
  for(const [prefix,p] of [['source',r.source],['target',r.target]]) {
    for(const getter of ['ASSET','SCOPE','VERIFIER','HOLDER_EXIT_VERIFIER','ASP_REGISTRY'])add(`${prefix}.${getter}`,p.pool,PRIVACY_POOL_ABI,getter);
    add(`${prefix}.PROVIDER`,p.registry,REGISTRY_ABI,'PROVIDER');
  }
  for(const role of ['router','quoter'])for(const getter of ['factory','WETH9'])add(`${role}.${getter}`,r[role],PERIPHERY_ABI,getter);
  const expected={SOURCE_POOL:r.sourcePool,TARGET_POOL:r.targetPool,ROUTER:r.router,WRAPPED_NATIVE:r.wrappedNative,FACTORY:r.factory,
    TOKEN_IN:r.tokens[0],TOKEN_OUT:r.tokens.at(-1),SOURCE_ASSET:r.source.asset,TARGET_ASSET:r.target.asset};
  if(r.paid){add('adapter.FEE_BPS',r.adapter,ADAPTER_ABI,'FEE_BPS');expected.TREASURY=r.treasury;}
  for(const getter of [...Object.keys(expected),'PROTOCOL','HOPS','SOURCE_NATIVE','TARGET_NATIVE','PATH_HASH','PATH','routeTokens','hopPools'])add(`adapter.${getter}`,r.adapter,ADAPTER_ABI,getter);
  r.hops.forEach((hop,i)=>{
    add(`hop${i}.registered`,r.factory,FACTORY_ABIS[r.protocol],'getPool',[hop.tokenIn,hop.tokenOut,hop.parameter]);
    for(const getter of ['token0','token1','factory',r.protocol===0?'fee':'tickSpacing','liquidity'])add(`hop${i}.${getter}`,hop.pool,DEX_POOL_ABI,getter);
  });
  const values=await bounded(specs,spec=>{const {key,...call}=spec;return client.readContract({...call,blockNumber});}),got=new Map(specs.map((s,i)=>[s.key,values[i]]));
  for(const [prefix,p] of [['source',r.source],['target',r.target]])must(same(got.get(`${prefix}.ASSET`),p.asset) && got.get(`${prefix}.SCOPE`)===p.scope
    && same(got.get(`${prefix}.VERIFIER`),p.verifier) && same(got.get(`${prefix}.HOLDER_EXIT_VERIFIER`),p.exitVerifier)
    && same(got.get(`${prefix}.ASP_REGISTRY`),p.registry) && same(got.get(`${prefix}.PROVIDER`),p.provider),'ROUTE_PRIVACY_POOL_MISMATCH');
  for(const role of ['router','quoter'])must(same(got.get(`${role}.factory`),r.factory) && same(got.get(`${role}.WETH9`),r.wrappedNative),'ROUTE_PERIPHERY_MISMATCH');
  for(const [getter,value] of Object.entries(expected))must(same(got.get(`adapter.${getter}`),value),'ROUTE_ADAPTER_MISMATCH');
  if(r.paid)must(integer(got.get('adapter.FEE_BPS'),100n,true)===BigInt(r.feeBps),'ROUTE_FEE_IMMUTABLE_MISMATCH');
  must(integer(got.get('adapter.PROTOCOL'),1n)===BigInt(r.protocol) && integer(got.get('adapter.HOPS'),4n,true)===BigInt(r.hops.length)
    && got.get('adapter.SOURCE_NATIVE')===r.wrapNative && got.get('adapter.TARGET_NATIVE')===r.unwrapNative
    && same(got.get('adapter.PATH_HASH'),r.pathHash) && same(got.get('adapter.PATH'),r.path),'ROUTE_ADAPTER_MISMATCH');
  for(const [getter,expected] of [['routeTokens',r.tokens],['hopPools',r.hops.map(h=>h.pool)]]){
    const values=got.get(`adapter.${getter}`);must(Array.isArray(values) && values.length===expected.length && values.every((v,i)=>same(v,expected[i])),'ROUTE_ADAPTER_TOPOLOGY_MISMATCH');
  }
  r.hops.forEach((hop,i)=>{
    must(same(got.get(`hop${i}.registered`),hop.pool),'ROUTE_FACTORY_POOL_MISMATCH');
    const a=address(got.get(`hop${i}.token0`)),b=address(got.get(`hop${i}.token1`));
    must(a!==b && [a,b].includes(hop.tokenIn) && [a,b].includes(hop.tokenOut) && same(got.get(`hop${i}.factory`),r.factory),'ROUTE_POOL_TOKENS_MISMATCH');
    must(integer(got.get(`hop${i}.${r.protocol===0?'fee':'tickSpacing'}`),r.protocol===0?999999n:0x7fffffn,true)===BigInt(hop.parameter),'ROUTE_POOL_PARAMETER_MISMATCH');
    must(integer(got.get(`hop${i}.liquidity`),MAX_VALUE)>0n,'ROUTE_POOL_LIQUIDITY_MISSING');
  });
  const quoted=await client.simulateContract({address:r.quoter,abi:QUOTER_ABI,functionName:'quoteExactInput',args:[r.path,amountIn],blockNumber}),result=quoted?.result;
  must(Array.isArray(result) && result.length===4 && Array.isArray(result[1]) && Array.isArray(result[2]) && result[1].length===r.hops.length && result[2].length===r.hops.length,'INVALID_ROUTE_QUOTE_RESULT');
  const amountOut=integer(result[0],MAX_VALUE,true),gasEstimate=integer(result[3]);
  for(const value of result[1])integer(value,(1n<<160n)-1n,true);
  for(const value of result[2])integer(value,0xffffffffn);
  const minAmountOut=amountOut*BigInt(10000-slippageBPS)/10000n;must(minAmountOut>0n,'QUOTE_OUTPUT_TOO_SMALL');
  const deadline=block.timestamp+BigInt(deadlineSeconds);must(deadline<=MAX_UINT256,'QUOTE_DEADLINE_OVERFLOW');
  let targetCapacity;
  if(r.targetCapacityRequired){
    const snapshot=await readTargetCapacitySnapshot({client,targetProfile:r.targetProfile,blockNumber,blockHash:block.hash});
    targetCapacity=assertQuotedTargetCapacity({quote:{chainId:r.chainId,targetPool:r.targetPool,targetAsset:r.targetAsset,blockNumber,blockHash:block.hash,
      amountOut,serviceFeeBps:r.paid?r.feeBps:0},snapshot});
    targetCapacity={...targetCapacity,integrationStatus:'quote-enforced-when-configured',proofWalletCheckRequired:true,finalFullCallSimulationRequired:true};
  }
  must((await blockAt(client,blockNumber)).hash===block.hash && await client.getChainId()===r.chainId,'QUOTE_SNAPSHOT_CHANGED');
  return {schema:'phase2-asp-route-quote/v1',routeId:r.id,protocol:r.protocolName,chainId:r.chainId,sourcePool:r.sourcePool,targetPool:r.targetPool,
    sourceAsset:r.sourceAsset,targetAsset:r.targetAsset,sourceNoteModel:r.source.noteModel,targetNoteModel:r.target.noteModel,
    adapter:r.adapter,router:r.router,factory:r.factory,quoter:r.quoter,wrappedNative:r.wrappedNative,path:r.path,hops:r.hops.length,
    tokenIn:r.tokens[0],tokenOut:r.tokens.at(-1),wrapNative:r.wrapNative,unwrapNative:r.unwrapNative,
    amountIn,amountOut,minAmountOut,minAmountOutKind:'gross-dex-output',amountOutKind:'gross-dex-output',slippageBPS,deadline,blockNumber,blockHash:block.hash,gasEstimate,
    adapterType:r.adapterType,serviceFeeBps:r.paid?r.feeBps:0,treasury:r.paid?r.treasury:null,netQuote:netPhase2Quote({grossAmountOut:amountOut,serviceFeeBps:r.paid?r.feeBps:0,slippageBPS}),
    ...(targetCapacity?{targetCapacity}:{}),deployment:r.deployment,priceContext:r.source.chainId===4663?'Pinned public Robinhood mainnet DEX quote; amounts and route are visible on chain.':r.priceContext,...releaseFlags,transactionsSent:false};
}
