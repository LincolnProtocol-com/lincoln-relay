// SPDX-License-Identifier: Apache-2.0
// Token sweep: at most one relay -> fixed Safe ERC-20 transfer per hour.
//
// The relay pays gas only in ETH and never spends a pool token, so every token
// it holds is fee income: the whole balance moves once it is worth ten gas
// quotes. ETH is never swept here (it is the relay's gas working capital).
// No log scan: one run is a few balance reads. Debits and pending entries come
// from the shared signer ledger, rechecked while its lock is held.
import {openServiceStore} from '../phase1-service/store.mjs';
import {TREASURY_KIND,TREASURY_NATIVE,TREASURY_RELAY,TREASURY_SAFE,TREASURY_POLICY,TREASURY_TRANSFER_ABI,treasuryId} from './treasury-intent.mjs';

export const TREASURY_JOURNAL_SCHEMA='lincoln-mainnet-treasury-journal/v1';
export const TREASURY_JOURNAL_IDENTITY=`lincoln-mainnet-treasury:4663:${TREASURY_RELAY}`;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const units=(v,code='MAINNET_TREASURY_UNITS_INVALID')=>{need(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v),code);return BigInt(v);};
const settled=e=>['confirmed','reverted'].includes(e.status);
const live=e=>!['confirmed','reverted','cancelled'].includes(e.status);
const json=value=>JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?String(v):v));

/** Token pools as {id,address,asset,thresholdUnits|null}; the ETH pool is dropped. */
export function treasuryTokenPools(pools){
  need(Array.isArray(pools)&&pools.length>0&&pools.length<=64,'MAINNET_TREASURY_POOLS_INVALID');
  const ids=new Set(),out=[];
  for(const p of pools){
    need(/^[a-z][a-z0-9_-]{0,63}$/.test(p.id)&&!ids.has(p.id)&&/^0x[0-9a-fA-F]{40}$/.test(p.address)&&/^0x[0-9a-fA-F]{40}$/.test(p.asset)
      &&(p.thresholdUnits===null||/^[1-9][0-9]*$/.test(p.thresholdUnits)),'MAINNET_TREASURY_POOLS_INVALID');
    ids.add(p.id);
    if(p.asset.toLowerCase()!==TREASURY_NATIVE)out.push({id:p.id,address:p.address.toLowerCase(),asset:p.asset.toLowerCase(),thresholdUnits:p.thresholdUnits});
  }
  return out;
}
export function emptyTreasuryJournal(){
  return {schema:TREASURY_JOURNAL_SCHEMA,relay:TREASURY_RELAY,safe:TREASURY_SAFE,pools:{},sequence:0,inFlight:null,lastSweep:null,history:[]};
}
function validJournal(value){
  need(value?.schema===TREASURY_JOURNAL_SCHEMA&&value.relay===TREASURY_RELAY&&value.safe===TREASURY_SAFE
    &&value.pools&&typeof value.pools==='object'&&Number.isSafeInteger(value.sequence)&&value.sequence>=0&&Array.isArray(value.history),'MAINNET_TREASURY_JOURNAL_INVALID');
  return value;
}
export async function openTreasuryJournal({directory}){
  return openServiceStore({directory,identity:TREASURY_JOURNAL_IDENTITY,filename:'treasury.json'});
}

/** Live entries and confirmed transfers per asset from the shared ledger.
 * `excludeId` drops the reservation being authorized (it is in the ledger then). */
export function treasuryLedgerDebits(ledger,{excludeId}={}){
  need(ledger&&Array.isArray(ledger.entries),'MAINNET_TREASURY_LEDGER_INVALID');
  const out={swept:{},live:[],lastSweepId:null};
  for(const e of ledger.entries){
    if(e.id===excludeId)continue;
    if(!settled(e)&&live(e))out.live.push({id:e.id,status:e.status,kind:e.kind??null});
    if(e.kind===TREASURY_KIND&&e.status==='confirmed'){out.swept[e.treasuryAsset]=(out.swept[e.treasuryAsset]??0n)+units(e.treasuryAmount);out.lastSweepId=e.id;}
  }
  return out;
}

/** Pick at most one transfer. Pure: callers pass every chain read. */
export function planTreasuryTransfer({journal,pools,ledger,balances,nowTimestamp}){
  pools=treasuryTokenPools(pools);
  const base={schema:'lincoln-mainnet-treasury-plan/v2',chainId:4663,relay:TREASURY_RELAY,treasury:TREASURY_SAFE,
    policy:{intervalSeconds:TREASURY_POLICY.intervalSeconds,tokenThresholdGasQuotes:TREASURY_POLICY.tokenThresholdGasQuotes,ethSwept:false}};
  const debits=treasuryLedgerDebits(ledger);
  const rows=[...new Set(pools.map(p=>p.asset))].map(asset=>{
    const pool=pools.find(p=>p.asset===asset),balance=balances[asset]??0n;
    const threshold=pool.thresholdUnits===null?null:BigInt(pool.thresholdUnits)*BigInt(TREASURY_POLICY.tokenThresholdGasQuotes);
    return {poolId:pool.id,asset,balanceUnits:String(balance),sweptUnits:String(debits.swept[asset]??0n),
      thresholdUnits:threshold===null?null:String(threshold),eligible:threshold!==null&&balance>=threshold};
  });
  const summary={...base,assets:rows};
  if(debits.live.length)return {...summary,decision:'skip',reason:'PENDING_ACCOUNT_TRANSACTION'};
  if(journal.lastSweep&&BigInt(nowTimestamp)<BigInt(journal.lastSweep.blockTimestamp)+BigInt(TREASURY_POLICY.intervalSeconds))
    return {...summary,decision:'skip',reason:'INTERVAL_NOT_ELAPSED'};
  // Least recently transferred token first.
  const last=asset=>journal.history.filter(h=>h.asset===asset&&h.status==='confirmed').at(-1)?.blockTimestamp??'0';
  const choice=rows.filter(r=>r.eligible).sort((a,b)=>Number(BigInt(last(a.asset))-BigInt(last(b.asset)))||a.poolId.localeCompare(b.poolId))[0];
  if(!choice)return {...summary,decision:'skip',reason:'NO_ELIGIBLE_BALANCE'};
  const sequence=journal.sequence+1;
  return {...summary,decision:'transfer',transfer:{id:treasuryId(choice.asset,sequence),sequence,asset:choice.asset,amount:choice.balanceUnits,poolId:choice.poolId}};
}

async function balanceOf(client,asset){
  return client.readContract({address:asset,abi:TREASURY_TRANSFER_ABI,functionName:'balanceOf',args:[TREASURY_RELAY],blockTag:'latest'});
}

/** The signer calls this while holding the shared ledger lock (prepare and the
 * first broadcast): a pool token only, the journalled intent, nothing else in
 * flight, and no more than the relay holds now. */
export function createTreasuryAuthorizer({client,journal,pools}){
  pools=treasuryTokenPools(pools);
  return async({phase,entry,ledger})=>{
    need(['prepare','broadcast'].includes(phase)&&entry?.kind===TREASURY_KIND&&entry.treasuryAsset!==TREASURY_NATIVE
      &&pools.some(p=>p.asset===entry.treasuryAsset),'MAINNET_TREASURY_AUTHORIZATION_INVALID');
    need(journal.inFlight?.id===entry.id&&journal.inFlight.amount===entry.treasuryAmount&&journal.inFlight.asset===entry.treasuryAsset,'MAINNET_TREASURY_NOT_JOURNALLED');
    need(treasuryLedgerDebits(ledger,{excludeId:entry.id}).live.length===0,'MAINNET_TREASURY_PENDING_ENTRY');
    need(BigInt(entry.treasuryAmount)<=await balanceOf(client,entry.treasuryAsset),'MAINNET_TREASURY_AMOUNT_EXCEEDS_BALANCE');
  };
}

const terminalHistory=(journal,entry,extra={})=>{
  journal.history.push({id:entry.id,asset:entry.treasuryAsset,amount:entry.treasuryAmount,status:entry.status,hash:entry.hash??null,...extra});
  if(journal.history.length>512)journal.history.splice(0,journal.history.length-512);
};

/** One run. mode 'dry-run' never constructs or touches the signer; 'activate'
 * prepares and broadcasts at most one transfer and never resends. */
export async function runTreasurySweep({mode,client,store,pools,readLedger,executor,nowTimestamp,waitMs=60000,sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
  need(['dry-run','activate'].includes(mode),'MAINNET_TREASURY_MODE_INVALID');
  const journal=validJournal(await store.read()??emptyTreasuryJournal());
  const result=base=>json({mode,automaticResend:false,...base});
  if(mode==='activate'){
    need(executor&&typeof executor.prepareTreasury==='function','MAINNET_TREASURY_EXECUTOR_REQUIRED');
    const ledger=await executor.reconcile({activeOnly:true});
    if(journal.inFlight){
      const entry=ledger.entries.find(e=>e.id===journal.inFlight.id);
      if(!entry){journal.inFlight=null;await store.write(journal);}
      else if(['unknown','rejected','conflicted'].includes(entry.status))
        return result({decision:'paused',reason:'OPERATOR_REVIEW_REQUIRED',id:entry.id,status:entry.status,hash:entry.hash??null});
      else if(['broadcasting','submitted'].includes(entry.status))return finish(entry.id);
      else if(['prepared','signed'].includes(entry.status))return send(entry.id);
      else return record(entry);
    }
  }
  const ledger=mode==='activate'?await executor.status():await readLedger();
  const balances={};for(const asset of new Set(treasuryTokenPools(pools).map(p=>p.asset)))balances[asset]=await balanceOf(client,asset);
  const plan=planTreasuryTransfer({journal,pools,ledger,balances,nowTimestamp});
  if(mode==='dry-run'||plan.decision!=='transfer')return result({...plan,transactionsBroadcast:0});
  // Journal the intent before the signer can persist it: a crash in between
  // leaves an ID that the next run either finds (resume) or not (clear).
  journal.inFlight={id:plan.transfer.id,sequence:plan.transfer.sequence,asset:plan.transfer.asset,amount:plan.transfer.amount};
  journal.sequence=plan.transfer.sequence;await store.write(journal);
  executor.setAuthorizer(createTreasuryAuthorizer({client,journal,pools}));
  try{await executor.prepareTreasury({asset:plan.transfer.asset,amount:plan.transfer.amount,sequence:plan.transfer.sequence});}
  catch(error){
    const after=await executor.status().catch(()=>null);
    if(after&&!after.entries.some(e=>e.id===plan.transfer.id)){journal.inFlight=null;await store.write(journal);}
    if(['STORE_LOCKED','MAINNET_ACCOUNT_PENDING_TRANSACTION'].includes(error.code))return result({...plan,decision:'busy',reason:error.code,transactionsBroadcast:0});
    throw error;
  }
  return send(plan.transfer.id);

  async function send(id){
    executor.setAuthorizer(createTreasuryAuthorizer({client,journal,pools}));
    try{await executor.broadcast(id);}
    catch(error){
      if(error.code==='MAINNET_BROADCAST_UNKNOWN'||error.code==='MAINNET_BROADCAST_REJECTED')
        return result({decision:'paused',reason:error.code,id,transactionsBroadcast:1,hash:error.transactionHash??null});
      // Provably unsigned and not broadcast: release the account for relays.
      const state=await executor.status(),entry=state.entries.find(e=>e.id===id);
      if(entry?.status==='prepared'&&!entry.hash){await executor.cancelPrepared(id);journal.inFlight=null;await store.write(journal);}
      throw error;
    }
    return finish(id);
  }
  async function finish(id){
    const deadline=Date.now()+waitMs;
    for(;;){
      const state=await executor.reconcile({activeOnly:true}),entry=state.entries.find(e=>e.id===id);
      if(entry&&['confirmed','reverted'].includes(entry.status))return record(entry);
      if(Date.now()>=deadline)return result({decision:'submitted',reason:'AWAITING_RECEIPT',id,hash:entry?.hash??null,transactionsBroadcast:1});
      await sleep(2000);
    }
  }
  async function record(entry){
    const block=await client.getBlock({blockNumber:BigInt(entry.blockNumber)});
    const blockTimestamp=String(block.timestamp);
    terminalHistory(journal,entry,{blockNumber:entry.blockNumber,blockTimestamp});
    if(entry.status==='confirmed')journal.lastSweep={id:entry.id,hash:entry.hash,blockTimestamp};
    journal.inFlight=null;await store.write(journal);
    return result({decision:entry.status==='confirmed'?'transferred':'reverted',id:entry.id,asset:entry.treasuryAsset,amount:entry.treasuryAmount,
      hash:entry.hash,feeWei:entry.feeWei,transactionsBroadcast:1});
  }
}
