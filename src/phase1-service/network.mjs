// SPDX-License-Identifier: Apache-2.0
// Explicit Host/Origin policy. Forwarded headers never grant access.
const LOOPBACK=new Set(['127.0.0.1','localhost','[::1]']);
const fail=()=>{throw Object.assign(new Error('INVALID_NETWORK_POLICY'),{code:'INVALID_NETWORK_POLICY'});};
function hostURL(value){
  if(typeof value!=='string'||!value||/[\s/@?#\\]/.test(value))return null;
  try{const u=new URL(`http://${value}`);return u.pathname==='/'&&!u.username&&!u.password?u:null;}catch{return null;}
}
function originURL(value){
  if(typeof value!=='string'||!/^https?:\/\//.test(value))return null;
  try{const u=new URL(value);return !u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash&&value===u.origin?u:null;}catch{return null;}
}
export function createNetworkPolicy(env=process.env){
  const list=key=>env[key]===undefined?[]:env[key].split(',').map(x=>x.trim());
  const hosts=list('PHASE1_ALLOWED_HOSTS').map(value=>{const u=hostURL(value);if(!u||value.includes('*'))fail();return u.host;});
  const origins=list('PHASE1_ALLOWED_ORIGINS').map(value=>{const u=originURL(value);if(!u)fail();return u.origin;});
  return {
    allows(host,origin){
      const h=hostURL(host);if(!h||!LOOPBACK.has(h.hostname)&&!hosts.includes(h.host))return false;
      if(origin===undefined)return true;
      const o=originURL(origin);return Boolean(o&&(o.protocol==='http:'&&LOOPBACK.has(o.hostname)||origins.includes(o.origin)));
    }
  };
}
export function listenOptions(env=process.env,{testnet=false,host,port}={}){
  host??=env.PHASE1_HOST??'127.0.0.1';port??=env.PHASE1_PORT===undefined?(testnet?8792:8791):Number(env.PHASE1_PORT);
  if(typeof host!=='string'||!['127.0.0.1','0.0.0.0','::1','::','localhost'].includes(host)||!Number.isInteger(port)||port<0||port>65535)fail();
  return {host,port};
}
