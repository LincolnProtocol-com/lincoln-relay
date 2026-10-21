// SPDX-License-Identifier: Apache-2.0
// A completed, structured JSON-RPC rejection is different from uncertain HTTP
// delivery. Never classify from viem's outer message, details, name alone or an
// arbitrary provider-supplied delivery/rejectionReason field.
const UNKNOWN=Object.freeze({rejectionReason:'UNKNOWN',delivery:'unknown'});
const REJECTED=Object.freeze(Object.fromEntries(['FEE_BELOW_BASE','INSUFFICIENT_FUNDS','NONCE_TOO_LOW']
  .map(rejectionReason=>[rejectionReason,Object.freeze({rejectionReason,delivery:'rejected'})])));
const KNOWN=Object.freeze({rejectionReason:'ALREADY_KNOWN',delivery:'accepted-known'});
const TRUSTED=new WeakMap(),ACCESSOR=Symbol('accessor');
const RPC_CODES=new Set([-32000,-32003]);
const WRAPPERS=new Set(['RpcRequestError','RpcError','InvalidInputRpcError','TransactionRejectedRpcError','UnknownRpcError',
  'TransactionExecutionError','FeeCapTooLowError','InsufficientFundsError','NonceTooLowError']);
const INTERRUPTIONS=new Set(['TimeoutError','HttpRequestError','WebSocketRequestError','SocketClosedError','AbortError',
  'SyntaxError','ParseError','ParseRpcError','JsonRpcParseError','ProviderDisconnectedError','ChainDisconnectedError']);
const NETWORK_CODES=new Set(['ETIMEDOUT','ESOCKETTIMEDOUT','ECONNRESET','ECONNREFUSED','ECONNABORTED','EPIPE',
  'ENOTFOUND','EAI_AGAIN','ABORT_ERR','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_BODY_TIMEOUT','UND_ERR_SOCKET']);
const NUMBER='[0-9]{1,78}',ADDRESS='0x[0-9a-fA-F]{40}';
const BASE_FEE_DETAIL=new RegExp('^max fee per gas less than block base fee: address '+ADDRESS
  +', maxFeePerGas: ('+NUMBER+'),? baseFee: ('+NUMBER+')$','i');
const FUNDS_DETAILS=[
  new RegExp('^insufficient funds for gas \\* price \\+ value: address '+ADDRESS+',? have '+NUMBER+' want '+NUMBER+'$','i'),
  new RegExp('^insufficient funds for gas \\* price \\+ value: balance '+NUMBER+', tx cost '+NUMBER+', overshot '+NUMBER+'$','i')];
const NONCE_DETAILS=[
  new RegExp('^nonce too low: next nonce '+NUMBER+', tx nonce '+NUMBER+'$','i'),
  new RegExp('^nonce too low: address '+ADDRESS+',? tx: '+NUMBER+' state: '+NUMBER+'$','i')];

function own(value,key){
  const descriptor=Object.getOwnPropertyDescriptor(value,key);
  return descriptor===undefined?undefined:Object.hasOwn(descriptor,'value')?descriptor.value:ACCESSOR;
}

function errorPrototype(value){
  for(let depth=0,prototype=Object.getPrototypeOf(value);prototype&&depth<8;depth++,prototype=Object.getPrototypeOf(prototype)){
    if(prototype===Error.prototype)return true;
    if(prototype===SyntaxError.prototype)return false;
  }
  return false;
}

function leafClassification(leaf){
  // viem preserves the parsed RPC error object as RpcRequestError.cause. Only
  // that finite JSON shape (or a directly supplied parsed leaf) is admissible.
  const prototype=Object.getPrototypeOf(leaf);
  if(prototype!==Object.prototype&&prototype!==null)return UNKNOWN;
  const keys=Reflect.ownKeys(leaf);
  if(!keys.includes('code')||!keys.includes('message')||keys.some(key=>!['code','message','data'].includes(key)))return UNKNOWN;
  const code=own(leaf,'code'),message=own(leaf,'message');
  if(!Number.isSafeInteger(code)||!RPC_CODES.has(code)||typeof message!=='string'||message.length>1024
    ||/[\x00-\x1f\x7f]/.test(message))return UNKNOWN;
  if(message==='max fee per gas less than block base fee')return REJECTED.FEE_BELOW_BASE;
  const base=BASE_FEE_DETAIL.exec(message);
  if(base)return BigInt(base[1])<BigInt(base[2])?REJECTED.FEE_BELOW_BASE:UNKNOWN;
  if(['insufficient funds','insufficient funds for gas * price + value'].includes(message)
    ||FUNDS_DETAILS.some(pattern=>pattern.test(message)))return REJECTED.INSUFFICIENT_FUNDS;
  if(message==='nonce too low'||NONCE_DETAILS.some(pattern=>pattern.test(message)))return REJECTED.NONCE_TOO_LOW;
  if(message==='already known')return KNOWN;
  return UNKNOWN;
}

/** Fixed enums only. A nonce rejection does not prove a previous hash unmined;
 * the signer must independently reconcile hash, receipt and account nonce.
 * Any transport/parse interruption, unknown wrapper, accessor, cycle, truncated
 * chain, unrecognised code/message, or conflicting numeric fee detail is unknown.
 */
export function classifyMainnetBroadcastError(error){
  try{
    const seen=new Set();let current=error;
    for(let depth=0;depth<12;depth++){
      if(!current||typeof current!=='object'||seen.has(current))return UNKNOWN;
      seen.add(current);
      const name=own(current,'name'),code=own(current,'code'),status=own(current,'status'),cause=own(current,'cause');
      if([name,code,status,cause].includes(ACCESSOR)||INTERRUPTIONS.has(name)||NETWORK_CODES.has(code)
        ||status!==undefined||Object.getPrototypeOf(current)===SyntaxError.prototype)return UNKNOWN;
      // This brand lives only in this module; JSON-RPC data cannot forge it.
      const trusted=TRUSTED.get(current);if(trusted)return trusted;
      if(cause===undefined||cause===null)return leafClassification(current);
      if(!WRAPPERS.has(name)||!errorPrototype(current))return UNKNOWN;
      current=cause;
    }
    return UNKNOWN;
  }catch{return UNKNOWN;}
}

/** The RPC sanitizer alone attaches a fixed classification to its new Error.
 * Keeping a private identity brand allows viem to wrap that sanitized Error
 * again without requiring raw messages/causes or trusting wire-supplied enums.
 */
export function attachMainnetBroadcastClassification(clean,original){
  const classification=classifyMainnetBroadcastError(original);
  Object.defineProperties(clean,{
    rejectionReason:{value:classification.rejectionReason,enumerable:true},
    delivery:{value:classification.delivery,enumerable:true}});
  TRUSTED.set(clean,classification);
  return clean;
}
