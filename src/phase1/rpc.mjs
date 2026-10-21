// SPDX-License-Identifier: Apache-2.0
// Repeat only transient public reads, never signing, submission or mutations.
const READS=new Set(['getBlock','getBlockNumber','getCode','getStorageAt','getLogs','readContract','getBalance','getChainId','getTransaction','getTransactionReceipt','getTransactionCount','getGasPrice','estimateGas']);
function transient(error){
  for(let e=error,i=0;e&&i++<12;e=e.cause){
    if(e.name==='ContractFunctionRevertedError'||e.name==='ExecutionRevertedError')return false;
    if(typeof e.data==='string' && /^0x[\da-f]+$/i.test(e.data))return false;
  }
  for(let e=error,i=0;e&&i++<12;e=e.cause){
    if(['BlockNotFoundError','TimeoutError'].includes(e.name))return true;
    if(e.name==='HttpRequestError' && Number(e.status)>=500)return true;
    if(['ECONNRESET','ETIMEDOUT','EAI_AGAIN'].includes(e.code))return true;
    if([-32000,-32001].includes(e.code) && /block.*(?:not found|not available|unknown)|header not found/i.test(e.message??''))return true;
    // Some public backends intermittently reject a historical-block read or
    // estimation with generic -32602. Repeat identical arguments only, within
    // this same fixed bound; a persistent parameter bug is still surfaced.
    if([-32602,-32000].includes(e.code) && /missing or invalid parameters/i.test(e.message??''))return true;
  }
  return false;
}
export function withPhase1ReadRetries(client,{delays=[250,750,1500,2000],sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
  if(!Array.isArray(delays)||delays.length>4||!delays.every(x=>Number.isSafeInteger(x)&&x>=0&&x<=2000))throw new Error('Invalid bounded read retry delays.');
  const methods=new Map();
  return new Proxy(client,{get(target,key){
    const value=target[key];if(typeof value!=='function')return value;
    if(!READS.has(key))return value.bind(target);
    if(!methods.has(key))methods.set(key,async(...args)=>{
      for(let attempt=0;;attempt++)try{return await value.apply(target,args);}
      catch(error){if(attempt>=delays.length||!transient(error))throw error;await sleep(delays[attempt]);}
    });
    return methods.get(key);
  }});
}
