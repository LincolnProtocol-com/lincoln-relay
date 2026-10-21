#!/usr/bin/env node
// Mainnet target inventory and optional public RPC checks. No signer or broadcasts.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const ADDRESS=/^0x[0-9a-f]{40}$/i,HASH=/^0x[0-9a-f]{64}$/i;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const need=(ok,code)=>{if(!ok)fail(code);};
const clone=value=>JSON.parse(JSON.stringify(value));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

/** Metadata review only; presence never claims ceremony verification or deployment safety. */
export function buildMainnetPlan({config,productionBuild=null,joinManifest=null,exitManifest=null}={}){
  need(config?.schema==='lincoln-mainnet-target/v1'&&config.enabled===true&&config.network==='mainnet'&&config.chain?.id===4663,'MAINNET_TARGET_CHAIN_MISMATCH');
  need(config.chain.rpcUrl==='https://rpc.mainnet.chain.robinhood.com/'&&ADDRESS.test(config.deployer?.address??''),'MAINNET_TARGET_INVALID');
  const mode=config.deployment?.policyMode;
  need(mode===null||['asp','permissionless'].includes(mode),'MAINNET_POLICY_INVALID');
  if(mode==='asp')need(config.provider?.kind==='self-hosted'&&ADDRESS.test(config.provider.address)
    &&config.provider.bootstrapPolicy==='all-current-notes'&&config.provider.sourceScreening===false,'MAINNET_PROVIDER_INVALID');
  need(Array.isArray(config.codePins)&&config.codePins.length>0&&config.codePins.every(pin=>ADDRESS.test(pin.address)&&HASH.test(pin.runtimeCodeHash)),'MAINNET_PINS_INVALID');
  const pending=[],add=(code,detail)=>pending.push({code,detail});
  if(mode===null)add('POLICY_SELECTION_PENDING','Select ASP or a separately specified permissionless circuit; neither is selected automatically.');
  let buildStatus='missing';
  if(!productionBuild)add('PRODUCTION_BUILD_MISSING','Build a separately named mainnet binary; current development constructors remain unchanged.');
  else{
    const meta=productionBuild._meta;
    if(!meta||meta.testOnly!==false||meta.releaseCandidate!==true||JSON.stringify(meta.allowedChainIds)!=='[4663]'){
      buildStatus='rejected';add('DEVELOPMENT_BUILD_REJECTED','The supplied build is not an explicit mainnet release candidate.');
    }else if(mode!==null&&meta.policyMode!==mode){buildStatus='rejected';add('BUILD_POLICY_MISMATCH','Build must identify the selected spending policy.');}
    else buildStatus='candidate-metadata-present';
  }
  const circuits={};
  for(const [name,manifest]of [['joinsplit',joinManifest],['holder-exit',exitManifest]]){
    let status='missing';
    if(!manifest)add('PRODUCTION_CIRCUIT_MISSING',name+': final production parameters and verifier are not present.');
    else if(manifest.testOnly!==false||manifest.schema!=='phase2-asp-production-circuits/v1'||manifest.setup?.kind!=='multi-party-phase2'
      ||JSON.stringify(manifest.allowedChainIds)!=='[4663]'){
      status='rejected';add('DEVELOPMENT_PARAMETERS_REJECTED',name+': self-generated development keys cannot be adopted by changing chain labels.');
    }else if(manifest.inputs?.circuit!==name||manifest.counts?.outputs!==0||
      (name==='holder-exit'?manifest.counts.publicInputs!==5:!Number.isInteger(manifest.counts?.publicInputs)||manifest.counts.publicInputs<=0)){
      status='rejected';add('PRODUCTION_CIRCUIT_INTERFACE_INVALID',name+': interface metadata does not match the intended circuit.');
    }else if(name==='joinsplit'&&mode!==null&&manifest.inputs?.policyMode!==mode){
      status='rejected';add('CIRCUIT_POLICY_MISMATCH','JoinSplit parameters must identify the selected spending policy.');
    }else status='candidate-metadata-present';
    circuits[name]={status,path:config.productionArtifacts?.[name==='joinsplit'?'joinsplitManifest':'holderExitManifest']??null};
  }
  const limits=config.limits;
  if(!limits||!['gasBudgetWei','maxTotalFundingWei','maxDepositWei','maxFeePerGasWei'].every(key=>typeof limits[key]==='string'&&/^[1-9][0-9]{0,77}$/.test(limits[key])))
    add('MAINNET_LIMITS_UNSET','Record the concrete small-run funding and gas limits before creating a transaction plan.');
  return {schema:'lincoln-mainnet-plan/v1',mainnetTargetEnabled:true,network:'mainnet',chain:clone(config.chain),deployer:clone(config.deployer),
    policyMode:mode,selected:config.deployment.selected??null,provider:config.provider?clone(config.provider):null,
    deploymentBuildEnabled:config.deployment.deploymentBuildEnabled===true,
    sourceBuildPlanCommand:config.deployment.sourceBuildPlanCommand??null,
    productionCompileImplemented:config.deployment.productionCompileImplemented===true,
    policyOptions:['asp','permissionless'],assets:clone(config.assets),codePins:clone(config.codePins),
    build:{status:buildStatus,path:config.productionArtifacts?.build??null},circuits,limits:clone(limits??{}),
    audit:{status:config.audit?.status??'pending',blocking:false},
    readiness:{metadataComplete:pending.length===0,productionReady:false,cryptographicVerificationExecuted:false,
      deploymentPermitted:false,broadcastImplemented:config.deployment?.broadcastImplemented===true},pending,
    readOnly:true,offline:true,transactionsBroadcast:0,mainnetE2ECompleted:false,
    limitations:[...config.limitations,'This plan checks metadata; final zkey mathematics, verifier binding, build bytecode and funding transactions require separate preparation.']};
}

async function publicJSON(root,relative,{optional=false}={}){
  need(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(part=>part&&part!=='.'&&part!=='..'&&!part.startsWith('.')),'MAINNET_PUBLIC_PATH_REQUIRED');
  need(['config/','artifacts/phase2-mainnet/','protocol/phase2-mainnet/'].some(prefix=>relative.startsWith(prefix)),'MAINNET_PUBLIC_PATH_REQUIRED');
  const filename=path.resolve(root,relative);let stat;
  try{stat=await fs.lstat(filename);}catch(error){if(optional&&error.code==='ENOENT')return null;throw error;}
  need(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=8*1024*1024&&await fs.realpath(filename)===filename,'MAINNET_REGULAR_PUBLIC_FILE_REQUIRED');
  const bytes=await fs.readFile(filename);
  return {value:JSON.parse(bytes.toString('utf8')),path:relative,sha256:digest(bytes)};
}
export async function readMainnetPlan({root=ROOT}={}){
  root=await fs.realpath(root);
  const config=await publicJSON(root,'config/phase2-mainnet.json'),paths=config.value.productionArtifacts;
  need(paths&&typeof paths==='object','MAINNET_ARTIFACT_PATHS_REQUIRED');
  const [build,join,exit]=await Promise.all(['build','joinsplitManifest','holderExitManifest'].map(key=>publicJSON(root,paths[key],{optional:true})));
  const plan=buildMainnetPlan({config:config.value,productionBuild:build?.value,joinManifest:join?.value,exitManifest:exit?.value});
  plan.inputs=Object.fromEntries([['config',config],['build',build],['joinsplit',join],['holder-exit',exit]].map(([name,item])=>[name,item?{path:item.path,sha256:item.sha256}:null]));
  return plan;
}

/** Only public-client read methods are used; caller-supplied clients are for tests. */
export async function checkMainnetReadOnly({plan,client}={}){
  need(plan?.schema==='lincoln-mainnet-plan/v1'&&plan.chain?.id===4663,'MAINNET_PLAN_REQUIRED');
  need(client&&['getChainId','getBlockNumber','getBlock','getBalance','getTransactionCount','getCode'].every(name=>typeof client[name]==='function'),'MAINNET_READ_CLIENT_REQUIRED');
  need(await client.getChainId()===4663,'MAINNET_RPC_WRONG_CHAIN');
  const blockNumber=await client.getBlockNumber(),block=await client.getBlock({blockNumber});
  need(block.number===blockNumber&&HASH.test(block.hash),'MAINNET_BLOCK_INVALID');
  const [balanceWei,pendingNonce]=await Promise.all([
    client.getBalance({address:plan.deployer.address,blockNumber}),
    client.getTransactionCount({address:plan.deployer.address,blockTag:'pending'}),
  ]);
  const {keccak256}=await import('viem');
  const pins=[];
  for(const pin of plan.codePins){const code=await client.getCode({address:pin.address,blockNumber});
    pins.push({role:pin.role,address:pin.address,expected:pin.runtimeCodeHash,actual:code&&code!=='0x'?keccak256(code):null,
      matched:Boolean(code&&code!=='0x'&&keccak256(code).toLowerCase()===pin.runtimeCodeHash.toLowerCase())});}
  need(await client.getChainId()===4663&&(await client.getBlock({blockNumber})).hash===block.hash,'MAINNET_RPC_SNAPSHOT_CHANGED');
  return {schema:'lincoln-mainnet-readonly-check/v1',chainId:4663,blockNumber:String(blockNumber),blockHash:block.hash,
    deployer:{address:plan.deployer.address,balanceWei:String(balanceWei),pendingNonce:String(pendingNonce)},pins,
    allCodePinsMatched:pins.every(pin=>pin.matched),readOnly:true,transactionsBroadcast:0,
    limitations:['Code checks do not attest proxy implementation state, audit status or completed proving ceremonies.','A pending nonce is a read-only observation, not a reservation.']};
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const args=process.argv.slice(2);need(args.length===0||args.length===1&&args[0]==='--onchain','USAGE_MAINNET_PLAN_ONCHAIN');
    const plan=await readMainnetPlan();
    if(args[0]==='--onchain'){
      const {createPublicClient,http}=await import('viem');
      const client=createPublicClient({transport:http(plan.chain.rpcUrl,{retryCount:0,timeout:20000}),cacheTime:0});
      plan.onchain=await checkMainnetReadOnly({plan,client});plan.offline=false;
    }
    console.log(JSON.stringify(plan,null,2));
  }catch(error){console.error(JSON.stringify({readOnly:true,transactionsBroadcast:0,error:error.code??'MAINNET_PLAN_FAILED'}));process.exitCode=1;}
}
