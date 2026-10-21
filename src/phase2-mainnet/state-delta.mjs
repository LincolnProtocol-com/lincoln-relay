// SPDX-License-Identifier: Apache-2.0
// Incremental public state: what a client holding the snapshot at `from` needs
// to reach the current one. Pure; the relay supplies the canonical base hash.
export const STATE_DELTA_SCHEMA='phase2-asp-state-delta/v1',STATE_DELTA_MAX_AGE_BLOCKS=36000;
export const STATE_DELTA_PATH=/^\/v3\/state\/since\/(0|[1-9][0-9]{0,15})$/;
const LISTS=['receipts','deposits','exits','flows','policies'];
const refuse=code=>Object.assign(new Error(code),{code,status:409});

/** Index of the first entry after block `from`; lists are in chain order. */
export function fromIndex(list,from,blockOf=entry=>entry.blockNumber){
  let i=list.length;while(i>0&&BigInt(blockOf(list[i-1],i-1))>from)i--;return i;
}

/**
 * @param snapshot a verified phase2-asp-public-state/v1 snapshot (not mutated)
 * @param from     the client's base block (bigint)
 * @param baseBlockHash canonical hash of `from` as this relay sees it now
 * @param servedSet root -> leaves for association sets this relay has served
 * Lists carry "<name>From": the index of their first entry in the full list,
 * which must equal the client's cached length (contiguity). commitments align
 * with receipts and nullifiers with the snapshot's nullifierBlocks.
 */
export function buildStateDelta({snapshot,from,baseBlockHash,publisher={},servedSet=()=>undefined,maxAgeBlocks=STATE_DELTA_MAX_AGE_BLOCKS}){
  const head=BigInt(snapshot.blockNumber);
  if(typeof from!=='bigint'||from<0n)throw refuse('STATE_DELTA_INVALID');
  if(from>head)throw refuse('STATE_DELTA_AHEAD');
  if(head-from>BigInt(maxAgeBlocks))throw refuse('STATE_DELTA_TOO_OLD');
  const {checkpoint,nullifierBlocks,commitments,receipts,nullifiers,deposits,exits,flows,policies,asp,...scalars}=snapshot;
  if(!Array.isArray(nullifierBlocks)||nullifierBlocks.length!==nullifiers.length||commitments.length!==receipts.length)throw refuse('STATE_DELTA_UNAVAILABLE');
  const lists={receipts,deposits,exits,flows,policies},out={};
  for(const name of LISTS){const at=fromIndex(lists[name],from);out[name+'From']=at;out[name]=lists[name].slice(at);}
  const nullifiersFrom=fromIndex(nullifiers,from,(_,i)=>nullifierBlocks[i]);
  // The set the client should already hold is the one the registry pointed to
  // at its base block. A client whose cached root is not `baseRoot` (or, when
  // leavesUnchanged, not asp.root) must re-read /v3/association-set.
  const {leaves,...meta}=asp;let aspPart;
  const baseRoot=[...policies].reverse().find(policy=>BigInt(policy.blockNumber)<=from)?.root??null;
  if(!Array.isArray(leaves))aspPart={...meta,setAvailable:false,baseRoot};
  else if(baseRoot===asp.root)aspPart={...meta,setAvailable:true,baseRoot,leavesUnchanged:true};
  else{
    const old=baseRoot===null?undefined:servedSet(baseRoot);
    aspPart=Array.isArray(old)&&old.length<=leaves.length&&old.every((leaf,i)=>leaf===leaves[i])
      ?{...meta,setAvailable:true,baseRoot,leavesFrom:old.length,leaves:leaves.slice(old.length)}
      :{...meta,setAvailable:true,baseRoot,aspReset:true,leavesFrom:0,leaves:[...leaves]};
  }
  return {...scalars,...publisher,schema:STATE_DELTA_SCHEMA,baseSchema:snapshot.schema,delta:true,fromBlock:String(from),baseBlockHash,
    commitmentsFrom:out.receiptsFrom,commitments:commitments.slice(out.receiptsFrom),nullifiersFrom,nullifiers:nullifiers.slice(nullifiersFrom),...out,
    counts:{commitments:commitments.length,nullifiers:nullifiers.length,...Object.fromEntries(LISTS.map(name=>[name,lists[name].length]))},
    asp:aspPart};
}
