#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Container entry. Default is a dry run (token balance reads only, no signer, no
// keys). --activate is supplied by the host runner only when the operator's
// enable marker exists; it then sends at most one transfer to the fixed Safe.
import fs from 'node:fs/promises';
import path from 'node:path';
import {constants} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createMainnetRuntimeClient,MAINNET_GENESIS_HASH} from '../../src/phase2-mainnet/rpc.mjs';
import {createMainnetSigner} from '../../src/phase2-mainnet/signer.mjs';
import {TREASURY_RELAY,TREASURY_SAFE,TREASURY_NATIVE} from '../../src/phase2-mainnet/treasury-intent.mjs';
import {openTreasuryJournal,runTreasurySweep} from '../../src/phase2-mainnet/treasury-sweeper.mjs';

const CONFIG='/run/config/mainnet',STATE='/app/.phase1-private/phase2-mainnet';
const SIGNER_DIRECTORY=`${STATE}/signers/4663-${TREASURY_RELAY}`,TREASURY_DIRECTORY=`${STATE}/treasury`;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const filename=name=>typeof name==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9._-]*\.json$/.test(name);
async function readJSON(file){
  need(path.isAbsolute(file)&&path.normalize(file)===file,'MAINNET_TREASURY_FILE_INVALID');
  const handle=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{const stat=await handle.stat();need(stat.isFile()&&stat.size<=32*1024*1024,'MAINNET_TREASURY_FILE_INVALID');return JSON.parse(await handle.readFile('utf8'));}
  finally{await handle.close();}
}
export function treasurySweepArguments(args){
  need(args.length===0||args.length===1&&args[0]==='--activate','MAINNET_TREASURY_ARGUMENTS_INVALID');
  return {mode:args.length?'activate':'dry-run'};
}
/** Live policy and pools from the active configuration; nothing hard-coded but
 * the relay and Safe. Token thresholds come from each pool's gas quote. */
export async function loadTreasuryConfiguration(config=CONFIG){
  const runtime=await readJSON(`${config}/runtime.json`);
  need(runtime?.schema==='lincoln-mainnet-container/v1'&&runtime.chainId===4663&&filename(runtime.profileFile)
    &&runtime.governanceSafe?.toLowerCase()===TREASURY_SAFE&&runtime.relay?.address?.toLowerCase()===TREASURY_RELAY&&runtime.relay.enabled===true
    &&Array.isArray(runtime.poolIds),'MAINNET_TREASURY_RUNTIME_POLICY_INVALID');
  const policy={budgetWei:runtime.relay.budgetWei,maxFeePerGasWei:runtime.relay.maxFeePerGasWei,reserveWei:runtime.relay.reserveWei};
  const deployed=await readJSON(`${config}/${runtime.profileFile}`),pools=[];
  for(const id of runtime.poolIds){
    const profile=deployed.profiles?.[id];
    need(profile?.relayer?.toLowerCase()===TREASURY_RELAY&&profile.genesisHash===MAINNET_GENESIS_HASH,'MAINNET_TREASURY_PROFILE_INVALID');
    let thresholdUnits=null;const asset=profile.pool.asset.toLowerCase(),feeFile=runtime.serviceFeesFile?.[id];
    if(asset!==TREASURY_NATIVE&&filename(feeFile)){
      const fees=await readJSON(`${config}/${feeFile}`);
      if(typeof fees.gasFeeUnits==='string'&&/^[1-9][0-9]*$/.test(fees.gasFeeUnits))thresholdUnits=fees.gasFeeUnits;
    }
    pools.push({id,address:profile.pool.address,asset,startBlock:String(profile.pool.startBlock),runtimeCodeHash:profile.pool.runtimeCodeHash,thresholdUnits});
  }
  return {policy,pools};
}
async function readLedgerFile(){
  const encoded=await readJSON(`${SIGNER_DIRECTORY}/signer.json`);
  need(encoded?.schema==='phase1-service-store/v1'&&encoded.identity===`lincoln-mainnet-signer:4663:${TREASURY_RELAY}`&&Array.isArray(encoded.value?.entries),'MAINNET_TREASURY_LEDGER_INVALID');
  return encoded.value;
}
/** The signer adapter: same ledger directory, lock and policy as the relays. */
export function treasuryExecutor(signerOptions,factory=createMainnetSigner){
  let authorize=null;
  const signer=factory({...signerOptions,treasuryAuthorizer:async args=>{need(authorize,'MAINNET_TREASURY_AUTHORIZER_UNSET');return authorize(args);}});
  return {setAuthorizer(fn){authorize=fn;},prepareTreasury:x=>signer.prepareTreasury(x),broadcast:x=>signer.broadcast(x),
    reconcile:x=>signer.reconcile(x),status:()=>signer.status(),cancelPrepared:x=>signer.cancelPrepared(x)};
}
export async function runContainerTreasury(args,{client:injected,configuration,executorFactory=createMainnetSigner,store:injectedStore,readLedger=readLedgerFile}={}){
  const {mode}=treasurySweepArguments(args),{policy,pools}=configuration??await loadTreasuryConfiguration();
  const client=injected??await createMainnetRuntimeClient({env:{PHASE2_MAINNET_RPC_FILE:'/run/secrets/mainnet-rpc-url'}});
  const store=injectedStore??await openTreasuryJournal({directory:TREASURY_DIRECTORY});
  try{
    const executor=mode==='activate'?treasuryExecutor({client,address:TREASURY_RELAY,directory:SIGNER_DIRECTORY,expectedGenesisHash:MAINNET_GENESIS_HASH,...policy,
      keystoreFile:'/run/secrets/mainnet-relay.keystore.json',passwordFile:'/run/secrets/mainnet-relay.password'},executorFactory):null;
    const head=await client.getBlock({blockTag:'latest'});
    return await runTreasurySweep({mode,client,store,pools,readLedger,executor,nowTimestamp:String(head.timestamp)});
  }finally{if(!injectedStore)await store.close();client.close?.();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(await runContainerTreasury(process.argv.slice(2))));}
  catch(error){const code=error.code??error.message;console.error(JSON.stringify({schema:'lincoln-mainnet-treasury-result/v1',decision:'paused',
    error:/^[A-Z][A-Z0-9_]{1,100}$/.test(code)?code:'MAINNET_TREASURY_RUN_FAILED',automaticResend:false,
    ...(typeof error.transactionHash==='string'&&/^0x[0-9a-f]{64}$/i.test(error.transactionHash)?{transactionHash:error.transactionHash}:{})}));process.exitCode=1;}
}
