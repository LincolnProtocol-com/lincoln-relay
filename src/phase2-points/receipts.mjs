// SPDX-License-Identifier: Apache-2.0
// A fee receipt lets the relay attribute an already-paid service fee to a
// claim address the user chose. It names a public fee log only; it never
// references the input note, nullifier or proof.
import {hashTypedData,verifyTypedData} from 'viem';
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const ADDRESS=/^0x[0-9a-fA-F]{40}$/,HASH=/^0x[0-9a-f]{64}$/i,ZERO='0x0000000000000000000000000000000000000000';
export const RECEIPT_SCHEMA='lincoln-points-fee-receipt/v1';
export const RECEIPT_TYPES={FeeReceipt:[{name:'season',type:'string'},{name:'txHash',type:'bytes32'},{name:'logIndex',type:'uint256'},{name:'claimant',type:'address'},{name:'referrer',type:'address'}]};
export const receiptDomain=chainId=>({name:'Lincoln Points',version:'1',chainId});

export function normalizeReceipt(input){
  need(input&&Object.getPrototypeOf(input)===Object.prototype&&Object.keys(input).every(k=>['schema','chainId','season','txHash','logIndex','claimant','referrer','signer','signature'].includes(k)),'INVALID_RECEIPT');
  need(input.schema===RECEIPT_SCHEMA&&Number.isSafeInteger(input.chainId)&&input.chainId>0,'INVALID_RECEIPT');
  need(typeof input.season==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(input.season),'INVALID_RECEIPT_SEASON');
  need(typeof input.txHash==='string'&&HASH.test(input.txHash)&&typeof input.logIndex==='string'&&/^(0|[1-9][0-9]{0,9})$/.test(input.logIndex),'INVALID_RECEIPT_EVENT');
  need(ADDRESS.test(input.claimant??'')&&ADDRESS.test(input.referrer??ZERO)&&ADDRESS.test(input.signer??''),'INVALID_RECEIPT_ADDRESS');
  need(typeof input.signature==='string'&&/^0x[0-9a-f]{130}$/i.test(input.signature),'INVALID_RECEIPT_SIGNATURE');
  const claimant=input.claimant.toLowerCase(),referrer=(input.referrer??ZERO).toLowerCase();
  need(claimant!==ZERO&&claimant!==referrer,'INVALID_RECEIPT_ADDRESS');
  return {schema:RECEIPT_SCHEMA,chainId:input.chainId,season:input.season,txHash:input.txHash.toLowerCase(),logIndex:input.logIndex,claimant,referrer,signer:input.signer.toLowerCase(),signature:input.signature};
}
const message=r=>({season:r.season,txHash:r.txHash,logIndex:BigInt(r.logIndex),claimant:r.claimant,referrer:r.referrer});
export const receiptKey=r=>`${r.txHash}:${r.logIndex}`;
export function receiptDigest(receipt){const r=normalizeReceipt({...receipt,signature:receipt.signature??'0x'+'00'.repeat(65)});return hashTypedData({domain:receiptDomain(r.chainId),types:RECEIPT_TYPES,primaryType:'FeeReceipt',message:message(r)});}

/** account: a viem local account (relay keystore). Returns a wire receipt. */
export async function signFeeReceipt({account,chainId,season,txHash,logIndex,claimant,referrer=ZERO}){
  need(account&&typeof account.signTypedData==='function'&&ADDRESS.test(account.address),'RECEIPT_SIGNER_REQUIRED');
  const unsigned={schema:RECEIPT_SCHEMA,chainId,season,txHash,logIndex:String(logIndex),claimant,referrer,signer:account.address,signature:'0x'+'00'.repeat(65)};
  const r=normalizeReceipt(unsigned);
  const signature=await account.signTypedData({domain:receiptDomain(chainId),types:RECEIPT_TYPES,primaryType:'FeeReceipt',message:message(r)});
  return {...r,signature};
}

/** EOA recovery only. Smart-account signers are not accepted for relays. */
export async function verifyFeeReceipt(input,{chainId,season,relayers}){
  const r=normalizeReceipt(input);
  need(r.chainId===chainId&&r.season===season,'RECEIPT_SCOPE_MISMATCH');
  need(relayers.includes(r.signer),'RECEIPT_SIGNER_UNKNOWN');
  let ok=false;try{ok=await verifyTypedData({address:r.signer,domain:receiptDomain(chainId),types:RECEIPT_TYPES,primaryType:'FeeReceipt',message:message(r),signature:r.signature});}catch{ok=false;}
  need(ok,'RECEIPT_SIGNATURE_INVALID');
  return r;
}

// ---------------------------------------------------------------- payout address

/** Season-end payouts are private notes: the claimant signs, from the address that
 * earned the points, the pool receiving address the incentive Safe should deposit to. */
export const PAYOUT_SCHEMA='lincoln-points-payout-address/v1';
export const PAYOUT_TYPES={PayoutAddress:[{name:'season',type:'string'},{name:'claimant',type:'address'},{name:'pool',type:'address'},{name:'ownerPublicKey',type:'string'},{name:'encryptionPublicKey',type:'string'}]};
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export function normalizePayoutRegistration(input){
  need(input&&Object.getPrototypeOf(input)===Object.prototype&&Object.keys(input).every(k=>['schema','chainId','season','claimant','pool','ownerPublicKey','encryptionPublicKey','signature'].includes(k)),'INVALID_PAYOUT_REGISTRATION');
  need(input.schema===PAYOUT_SCHEMA&&Number.isSafeInteger(input.chainId)&&input.chainId>0,'INVALID_PAYOUT_REGISTRATION');
  need(typeof input.season==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(input.season),'INVALID_PAYOUT_SEASON');
  need(ADDRESS.test(input.claimant??'')&&ADDRESS.test(input.pool??''),'INVALID_PAYOUT_ADDRESS');
  need(typeof input.ownerPublicKey==='string'&&/^[1-9][0-9]{0,77}$/.test(input.ownerPublicKey)&&BigInt(input.ownerPublicKey)<FIELD,'INVALID_PAYOUT_RECEIVER');
  need(typeof input.encryptionPublicKey==='string'&&/^0x[0-9a-f]{64}$/i.test(input.encryptionPublicKey),'INVALID_PAYOUT_RECEIVER');
  need(typeof input.signature==='string'&&/^0x[0-9a-f]{130}$/i.test(input.signature),'INVALID_PAYOUT_SIGNATURE');
  return {schema:PAYOUT_SCHEMA,chainId:input.chainId,season:input.season,claimant:input.claimant.toLowerCase(),pool:input.pool.toLowerCase(),ownerPublicKey:input.ownerPublicKey,encryptionPublicKey:input.encryptionPublicKey.toLowerCase(),signature:input.signature};
}
const payoutMessage=r=>({season:r.season,claimant:r.claimant,pool:r.pool,ownerPublicKey:r.ownerPublicKey,encryptionPublicKey:r.encryptionPublicKey});
export async function signPayoutRegistration({account,chainId,season,pool,ownerPublicKey,encryptionPublicKey}){
  need(account&&typeof account.signTypedData==='function'&&ADDRESS.test(account.address),'PAYOUT_SIGNER_REQUIRED');
  const r=normalizePayoutRegistration({schema:PAYOUT_SCHEMA,chainId,season,claimant:account.address,pool,ownerPublicKey:String(ownerPublicKey),encryptionPublicKey,signature:'0x'+'00'.repeat(65)});
  const signature=await account.signTypedData({domain:receiptDomain(chainId),types:PAYOUT_TYPES,primaryType:'PayoutAddress',message:payoutMessage(r)});
  return {...r,signature};
}
/** The signer must be the claimant itself; nobody can redirect another address's payout. */
export async function verifyPayoutRegistration(input,{chainId,season}){
  const r=normalizePayoutRegistration(input);
  need(r.chainId===chainId&&r.season===season,'PAYOUT_SCOPE_MISMATCH');
  let ok=false;try{ok=await verifyTypedData({address:r.claimant,domain:receiptDomain(chainId),types:PAYOUT_TYPES,primaryType:'PayoutAddress',message:payoutMessage(r),signature:r.signature});}catch{ok=false;}
  need(ok,'PAYOUT_SIGNATURE_INVALID');
  return r;
}
