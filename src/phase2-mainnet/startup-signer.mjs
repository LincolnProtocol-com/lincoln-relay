// SPDX-License-Identifier: Apache-2.0
// One executor per API signing identity. Only an exclusive, gated startup may
// reuse its fully reconciled terminal ledger. No ordinary-runtime memo or retry.
import {createMainnetSigner} from './signer.mjs';

const groups=new WeakMap();
const terminal=new Set(['confirmed','reverted','cancelled']);
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const clone=value=>structuredClone(value);

/** The real account store still performs its unchanged validation/settlement.
 * The cache is closure-local, terminal-only, and disabled permanently by any
 * operation other than reconcile, or by finishStartup (including failed init).
 * The global queue prevents two pools racing to open the same account lock. */
export function createStartupReconcileWindow(base,{enabled=false}={}){
  need(base&&typeof base.reconcile==='function'&&typeof enabled==='boolean','MAINNET_STARTUP_EXECUTOR_INVALID');
  let startup=enabled,memo=null,tail=Promise.resolve();
  const invalidate=()=>{startup=false;memo=null;};
  const serial=task=>{const run=tail.then(task);tail=run.catch(()=>{});return run;};
  const executor={};
  for(const [key,value] of Object.entries(base)){
    if(typeof value!=='function'){executor[key]=value;continue;}
    if(key==='reconcile')continue;
    executor[key]=(...args)=>{
      // Invalidate BEFORE enqueueing and on both success/failure. An incoming
      // prepare/broadcast/status/recover/cancel cannot race a cached summary.
      invalidate();
      return serial(async()=>{try{return await value.apply(base,args);}finally{invalidate();}});
    };
  }
  executor.reconcile=(...args)=>{
    // Runtime active-only requests can never consume or establish a full-audit
    // startup memo. Invalidate synchronously, including invalid/failed calls,
    // so an already queued full reconciliation cannot memoize stale authority.
    if(args.length)invalidate();
    return serial(async()=>{
      if(startup&&memo!==null)return clone(memo);
      let result;try{result=await base.reconcile(...args);}catch(error){invalidate();throw error;}
      if(startup){
        const settled=Array.isArray(result?.entries)&&result.entries.every(entry=>terminal.has(entry.status));
        if(!settled)invalidate();
        need(settled,'MAINNET_STARTUP_SIGNER_UNRESOLVED');
        memo=clone(result);
      }
      return clone(result);
    });
  };
  return Object.freeze({executor:Object.freeze(executor),finishStartup:invalidate});
}

/** Opaque process-local group, never a JSON runtime verification bypass. */
export function createMainnetAPIExecutorGroup({startupMemo=false}={}){
  need(typeof startupMemo==='boolean','MAINNET_STARTUP_EXECUTOR_INVALID');
  const capability=Object.freeze({});
  groups.set(capability,{startupMemo,key:null,client:null,window:null,finished:false});
  return capability;
}

export function mainnetAPIExecutorFor(group,options){
  const state=groups.get(group);need(state&&!state.finished,'MAINNET_STARTUP_EXECUTOR_GROUP_INVALID');
  // Call the ORIGINAL factory for EVERY unit before considering reuse. This
  // retains its address, exact budget/reserve/cap and option validation.
  const validated=createMainnetSigner(options);
  const key=JSON.stringify(Object.fromEntries(['address','account','keystoreFile','passwordFile','budgetWei',
    'maxFeePerGasWei','reserveWei','expectedGenesisHash','root','directory'].map(name=>[name,options[name]??null])));
  need(options.signRawTransaction===undefined&&options.beforeBroadcast===undefined,'MAINNET_STARTUP_EXECUTOR_CUSTOM_SIGNER_DENIED');
  if(state.window===null){
    state.key=key;state.client=options.client;
    state.window=createStartupReconcileWindow(validated,{enabled:state.startupMemo});
  }else need(state.key===key&&state.client===options.client&&validated.address===state.window.executor.address
    &&validated.directory===state.window.executor.directory,'MAINNET_STARTUP_EXECUTOR_IDENTITY_MISMATCH');
  return state.window.executor;
}

export function finishMainnetAPIExecutorGroup(group){
  const state=groups.get(group);need(state,'MAINNET_STARTUP_EXECUTOR_GROUP_INVALID');
  state.finished=true;state.window?.finishStartup();
}
