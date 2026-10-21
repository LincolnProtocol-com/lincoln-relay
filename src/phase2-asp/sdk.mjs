// SPDX-License-Identifier: Apache-2.0
// Experimental factorized-note ASP JoinSplit client. Isolated from other Phase-2 note domains.
import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey,
  diffieHellman, hkdfSync, randomBytes, scryptSync } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants as fsConstants } from 'node:fs';
import { spawn } from 'node:child_process';
import { encodeAbiParameters, isAddress, keccak256, stringToHex } from 'viem';
import { poseidon } from 'maci-crypto/build/ts/hashing.js';

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const MAX_VALUE = (1n << 128n) - 1n;
export const TREE_DEPTH = 20;
export const RECEIPT_BYTES = 256;
export const NOTE_MODEL = 'factorized-asp-v1';
export const PROFILE_SCHEMA = 'phase2-asp-test-profile/v1';
export const PRODUCTION_PROFILE_SCHEMA = 'phase2-asp-production-profile/v1';
export const DOMAIN = keccak256(stringToHex('CHENG_PHASE2_ASP_V1'));
export const NATIVE_ASSET = '0x0000000000000000000000000000000000000000';
const PRIVATE_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const PUBLIC_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const BACKUP_N = 32768, BACKUP_R = 8, BACKUP_P = 1;
const MAX_BACKUP_BYTES = 8 * 1024 * 1024;
const MAX_NOTES = 10000;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const sha = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => `0x${Buffer.from(bytes).toString('hex')}`;
function check(value, message) { if (!value) throw new Error(message); }
function exactKeys(value, keys, name) {
  check(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(','), `Invalid ${name} fields.`);
}
export function field(value, max = FIELD - 1n, nonzero = false) {
  check(typeof value === 'bigint' || typeof value === 'string' && /^(0|[1-9]\d{0,77})$/.test(value), 'Canonical decimal integer required.');
  const result = BigInt(value);
  check(result >= 0n && result <= max && (!nonzero || result > 0n), 'Integer outside allowed range.');
  return result;
}
function bytes(value, length) {
  check(typeof value === 'string' && /^0x[0-9a-f]*$/i.test(value) && value.length === 2 + length * 2, 'Invalid fixed-size byte encoding.');
  return Buffer.from(value.slice(2), 'hex');
}
function address(value, name = 'address', nonzero = false) {
  check(isAddress(value) && (!nonzero || value.toLowerCase() !== NATIVE_ASSET), `Invalid ${name}.`);
  return value.toLowerCase();
}
function randomField() { for (;;) { const result = BigInt(hex(randomBytes(32))); if (result > 0n && result < FIELD) return result; } }
export function normalizeProfile(profile) {
  const production=profile?.schema===PRODUCTION_PROFILE_SCHEMA;
  if(production){
    check(profile.releaseCandidate===true && profile.testOnly===false && profile.productionReady===false && profile.experimental!==true && profile.chain?.id===4663 && profile.pool?.noteModel===NOTE_MODEL,'Explicit Robinhood mainnet ASP release-candidate profile required.');
    const refs=profile.production;
    check(/^[a-f0-9]{64}$/.test(profile.artifactSHA256??'') && refs?.build?.path==='artifacts/phase2-mainnet/contracts.json' && refs.build.sha256===profile.artifactSHA256,'Pinned production build required.');
    check(refs.releaseId===undefined||refs.releaseId===profile.artifactSHA256,'Production release identity mismatch.');
    for(const name of ['joinsplit','holder-exit'])check(refs?.manifests?.[name]?.path===`protocol/phase2-mainnet/build/${name}/manifest.json` && /^[a-f0-9]{64}$/.test(refs.manifests[name].sha256??''),'Pinned final production manifest required.');
    check(/^0x[0-9a-f]{64}$/i.test(profile.genesisHash??'') && [profile.pool,profile.verifier,profile.exitVerifier,profile.registry].every(pin=>/^0x[0-9a-f]{64}$/i.test(pin?.runtimeCodeHash??'')),'Pinned production deployment identity required.');
    for(const pin of [profile.pool,profile.registry])check(typeof pin.startBlock==='string' && /^(0|[1-9][0-9]*)$/.test(pin.startBlock),'Production deployment start block required.');
  }else check(profile?.schema === PROFILE_SCHEMA && profile.pool?.noteModel === NOTE_MODEL && profile?.experimental === true && profile.testOnly === true && profile.productionReady === false && Number.isSafeInteger(profile?.chain?.id) && [31341, 46630].includes(profile.chain.id), 'Explicit local or Robinhood testnet Phase-2 ASP factorized profile required.');
  const pool = address(profile.pool?.address ?? profile.protocol?.pool ?? profile.protocol?.nativePool, 'pool', true);
  const scope = BigInt(keccak256(encodeAbiParameters([{type:'bytes32'},{type:'uint256'},{type:'address'}], [DOMAIN, BigInt(profile.chain.id), pool]))) % FIELD;
  const supplied = profile.pool?.scope ?? profile.protocol?.scope;
  if (supplied !== undefined) check(field(supplied, FIELD - 1n, true) === scope, 'Pool scope does not match chain and pool.');
  check((profile.pool?.treeDepth ?? profile.protocol?.treeDepth ?? TREE_DEPTH) === TREE_DEPTH, 'Phase-2 tree depth mismatch.');
  const asset = address(profile.pool?.asset ?? profile.protocol?.asset ?? NATIVE_ASSET, 'asset');
  const registry=address(profile.registry?.address,'ASP registry',true),provider=address(profile.registry?.provider,'ASP provider',true);
  if(production){address(profile.verifier.address,'production verifier',true);address(profile.exitVerifier.address,'production exit verifier',true);check(new Set([pool,registry,profile.verifier.address.toLowerCase(),profile.exitVerifier.address.toLowerCase()]).size===4,'Production deployment roles must differ.');}
  return { chainId: profile.chain.id, pool, asset, scope, treeDepth: TREE_DEPTH, noteModel: NOTE_MODEL, registry, provider };
}
export function profileReleaseFlags(profile){normalizeProfile(profile);return profile.schema===PRODUCTION_PROFILE_SCHEMA?{testOnly:false,releaseCandidate:true,productionReady:false}:{testOnly:true,productionReady:false};}
export function profileDomain(profile) { const p=normalizeProfile(profile); return `${DOMAIN}:${p.chainId}:${p.pool}:${p.scope}:${NOTE_MODEL}`; }
export function createAccount(seed) {
  if (seed === undefined) seed = randomBytes(32).toString('hex');
  check(typeof seed === 'string' && /^[0-9a-f]{64}$/.test(seed), 'Account seed must be 32 bytes of lowercase hex.');
  return { version: 1, seed, notes: [] };
}
function accountSeed(account) {
  check(account?.version === 1 && typeof account.seed === 'string' && /^[0-9a-f]{64}$/.test(account.seed) && Array.isArray(account.notes) && account.notes.length <= MAX_NOTES, 'Invalid Phase-2 account.');
  return Buffer.from(account.seed, 'hex');
}
function derive(account, profile, purpose, counter = 0) {
  return createHmac('sha256', accountSeed(account)).update(`CHENG_PHASE2_ASP_ACCOUNT_V1:${profileDomain(profile)}:${purpose}:${counter}`).digest();
}
export function spendingSecret(account, profile) {
  for (let i=0;;i++) { const value=BigInt(hex(derive(account,profile,'spend',i))); if (value>0n && value<FIELD) return value; }
}
function encryptionKey(account, profile) {
  return createPrivateKey({key:Buffer.concat([PRIVATE_PREFIX,derive(account,profile,'receipt-x25519')]),format:'der',type:'pkcs8'});
}
function rawPublic(privateKey) { return createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32); }
function importPublic(raw) { return createPublicKey({key:Buffer.concat([PUBLIC_PREFIX,raw]),format:'der',type:'spki'}); }
export function receiverAddress(account, profile) {
  const p=normalizeProfile(profile);
  return {version:1,noteModel:NOTE_MODEL,chainId:p.chainId,pool:p.pool,scope:String(p.scope),ownerPublicKey:String(poseidon([spendingSecret(account,profile)])),encryptionPublicKey:hex(rawPublic(encryptionKey(account,profile)))};
}
export const receiveAddress = receiverAddress;
export function validateReceiver(receiver, profile) {
  exactKeys(receiver,['version','noteModel','chainId','pool','scope','ownerPublicKey','encryptionPublicKey'],'receiver');
  const p=normalizeProfile(profile);
  check(receiver.version===1 && receiver.noteModel===NOTE_MODEL && receiver.chainId===p.chainId && address(receiver.pool,'receiver pool',true)===p.pool && field(receiver.scope,FIELD-1n,true)===p.scope,'Receiver belongs to another chain or pool.');
  field(receiver.ownerPublicKey,FIELD-1n,true);
  const key=bytes(receiver.encryptionPublicKey,32);
  // Derivation also rejects low-order Curve25519 points, before preparing funds.
  const temporary=createPrivateKey({key:Buffer.concat([PRIVATE_PREFIX,Buffer.alloc(32,1)]),format:'der',type:'pkcs8'});
  check(!diffieHellman({privateKey:temporary,publicKey:importPublic(key)}).equals(Buffer.alloc(32)),'Invalid receiver encryption key.');
  return receiver;
}
export function createNote({value, receiver, blinding = randomField()}, profile) {
  validateReceiver(receiver,profile);
  const p=normalizeProfile(profile), v=field(value,MAX_VALUE), ownerPublicKey=field(receiver.ownerPublicKey,FIELD-1n,true), b=field(blinding,FIELD-1n,true);
  return {version:1,chainId:p.chainId,pool:p.pool,scope:p.scope,value:v,ownerPublicKey,blinding:b,commitment:v===0n?0n:poseidon([v,poseidon([ownerPublicKey,b])])};
}
export function notePrecommitment(note, profile) {
  const n=normalizeNote(note,profile);
  return poseidon([n.ownerPublicKey,n.blinding]);
}
function normalizeNote(note, profile) {
  exactKeys(note,['version','chainId','pool','scope','value','ownerPublicKey','blinding','commitment'],'note');
  const p=normalizeProfile(profile);
  check(note.version===1 && note.chainId===p.chainId && address(note.pool,'note pool',true)===p.pool && field(note.scope,FIELD-1n,true)===p.scope,'Note belongs to another chain or pool.');
  const value=field(note.value,MAX_VALUE),ownerPublicKey=field(note.ownerPublicKey,FIELD-1n,true),blinding=field(note.blinding,FIELD-1n,true),commitment=field(note.commitment);
  check(value===0n ? commitment===0n : poseidon([value,poseidon([ownerPublicKey,blinding])])===commitment,'Note commitment mismatch.');
  return {version:1,chainId:p.chainId,pool:p.pool,scope:p.scope,value,ownerPublicKey,blinding,commitment};
}
export function serializeNote(note, profile) { return JSON.stringify(normalizeNote(note,profile),(_,v)=>typeof v==='bigint'?String(v):v); }
export function deserializeNote(text, profile) {
  check(typeof text==='string' && text.length<=2048,'Invalid note encoding length.');
  let note; try { note=JSON.parse(text); } catch { throw new Error('Invalid note JSON.'); }
  return normalizeNote(note,profile);
}
export function nullifier(note, secret, profile) {
  const n=normalizeNote(note,profile),s=field(secret,FIELD-1n,true);
  check(poseidon([s])===n.ownerPublicKey,'Spending key does not own this note.');
  return poseidon([s,n.commitment,n.scope]);
}
function receiptAAD(profile, commitment) { return Buffer.from(`${profileDomain(profile)}:receipt:v1:${field(commitment)}`); }
function sharedKey(privateKey, publicKey, aad) {
  const shared=diffieHellman({privateKey,publicKey});
  check(!shared.equals(Buffer.alloc(32)),'Invalid receipt encryption key.');
  return Buffer.from(hkdfSync('sha256',shared,sha(aad),Buffer.from('CHENG_PHASE2_ASP_RECEIPT_AES256GCM_V1'),32));
}
function writeInteger(target,value,offset,size) { Buffer.from(value.toString(16).padStart(size*2,'0'),'hex').copy(target,offset); }
export function encryptReceipt(receiver, note, profile) {
  validateReceiver(receiver,profile);
  const n=normalizeNote(note,profile);
  check(n.ownerPublicKey===field(receiver.ownerPublicKey),'Receipt recipient does not own output.');
  const ephemeral=createPrivateKey({key:Buffer.concat([PRIVATE_PREFIX,randomBytes(32)]),format:'der',type:'pkcs8'});
  const aad=receiptAAD(profile,n.commitment),key=sharedKey(ephemeral,importPublic(bytes(receiver.encryptionPublicKey,32)),aad),iv=randomBytes(12);
  // Binary plaintext has no input IDs, deposit labels, EOA or sender address.
  const plain=randomBytes(195); plain[0]=1; writeInteger(plain,n.value,1,16); writeInteger(plain,n.blinding,17,32);
  const cipher=createCipheriv('aes-256-gcm',key,iv); cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]);
  return hex(Buffer.concat([Buffer.from([1]),rawPublic(ephemeral),iv,ciphertext,cipher.getAuthTag()]));
}
export function decryptReceipt(account, profile, commitment, encryptedOutput) {
  const data=bytes(encryptedOutput,RECEIPT_BYTES);
  check(data[0]===1,'Unsupported receipt version.');
  const aad=receiptAAD(profile,commitment),key=sharedKey(encryptionKey(account,profile),importPublic(data.subarray(1,33)),aad);
  const decipher=createDecipheriv('aes-256-gcm',key,data.subarray(33,45));
  decipher.setAAD(aad); decipher.setAuthTag(data.subarray(240,256));
  const plain=Buffer.concat([decipher.update(data.subarray(45,240)),decipher.final()]);
  check(plain[0]===1,'Unsupported receipt plaintext.');
  const note=createNote({value:BigInt(hex(plain.subarray(1,17))),blinding:BigInt(hex(plain.subarray(17,49))),receiver:receiverAddress(account,profile)},profile);
  check(note.commitment===field(commitment),'Recovered note does not match on-chain commitment.');
  return note;
}
function dynamicAAD(profile,precommitment) {
  return Buffer.from(`${profileDomain(profile)}:dynamic-receipt:v2:${field(precommitment,FIELD-1n,true)}`);
}
/** An amount-independent invoice. Only the receiver can decrypt its blinding. */
export function createDynamicReceiver(receiver,profile,{blinding=randomField()}={}) {
  validateReceiver(receiver,profile);
  const b=field(blinding,FIELD-1n,true),precommitment=poseidon([field(receiver.ownerPublicKey,FIELD-1n,true),b]);
  check(precommitment>0n,'Zero dynamic precommitment.');
  const ephemeral=createPrivateKey({key:Buffer.concat([PRIVATE_PREFIX,randomBytes(32)]),format:'der',type:'pkcs8'});
  const aad=dynamicAAD(profile,precommitment),key=sharedKey(ephemeral,importPublic(bytes(receiver.encryptionPublicKey,32)),aad),iv=randomBytes(12);
  // Dynamic ciphertext carries no amount. The canonical pool event supplies it.
  const plain=randomBytes(195);plain[0]=2;writeInteger(plain,b,1,32);
  const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]);
  return {precommitment,encryptedTemplate:hex(Buffer.concat([Buffer.from([2]),rawPublic(ephemeral),iv,ciphertext,cipher.getAuthTag()]))};
}
export function createDynamicReceive(account,profile,options) {
  return createDynamicReceiver(receiverAddress(account,profile),profile,options);
}
export function decryptDynamicReceipt(account,profile,event) {
  check(event && typeof event==='object','Canonical dynamic deposit event required.');
  const value=field(event.value??event.amount,MAX_VALUE,true),precommitment=field(event.precommitment,FIELD-1n,true),commitment=field(event.commitment,FIELD-1n,true);
  const data=bytes(event.encryptedTemplate??event.encryptedOutput,RECEIPT_BYTES);
  check(data[0]===2,'Unsupported dynamic receipt version.');
  const aad=dynamicAAD(profile,precommitment),key=sharedKey(encryptionKey(account,profile),importPublic(data.subarray(1,33)),aad);
  const decipher=createDecipheriv('aes-256-gcm',key,data.subarray(33,45));decipher.setAAD(aad);decipher.setAuthTag(data.subarray(240,256));
  const plain=Buffer.concat([decipher.update(data.subarray(45,240)),decipher.final()]);
  check(plain[0]===2,'Unsupported dynamic receipt plaintext.');
  const note=createNote({value,blinding:BigInt(hex(plain.subarray(1,33))),receiver:receiverAddress(account,profile)},profile);
  check(notePrecommitment(note,profile)===precommitment && note.commitment===commitment,'Recovered dynamic note does not match canonical deposit.');
  return note;
}
export function buildMerkleTree(leaves = []) {
  check(Array.isArray(leaves) && leaves.length<=2**TREE_DEPTH,'Invalid Merkle leaf count.');
  const values=leaves.map(v=>field(v,FIELD-1n,true));
  check(new Set(values.map(String)).size===values.length,'Duplicate Merkle commitments.');
  const zeros=[0n]; for(let level=0;level<TREE_DEPTH;level++) zeros.push(poseidon([zeros[level],zeros[level]]));
  const levels=[values];
  for(let level=0;level<TREE_DEPTH;level++) {
    const current=levels[level],next=[];
    for(let i=0;i<current.length;i+=2) next.push(poseidon([current[i],current[i+1]??zeros[level]]));
    levels.push(next);
  }
  const root=levels[TREE_DEPTH][0]??zeros[TREE_DEPTH];
  return {root,depth:TREE_DEPTH,zeros,leaves:values,generateProof(index) {
    check(Number.isSafeInteger(index) && index>=0 && index<values.length,'Invalid Merkle leaf index.');
    const siblings=[]; let cursor=index;
    for(let level=0;level<TREE_DEPTH;level++) {siblings.push(levels[level][cursor^1]??zeros[level]);cursor=Math.floor(cursor/2);}
    return {root,index,siblings};
  }};
}
function publicState(state, profile) {
  const p=normalizeProfile(profile);
  check(state?.noteModel===undefined || state.noteModel===NOTE_MODEL,'Public state note model mismatch.');
  check(state && (state.chainId===undefined||state.chainId===p.chainId) && (state.pool===undefined||address(state.pool,'state pool',true)===p.pool) && (state.scope===undefined||field(state.scope,FIELD-1n,true)===p.scope),'Public state belongs to another chain or pool.');
  const tree=buildMerkleTree(state.commitments??state.stateLeaves);
  check(field(state.root??state.currentRoot)===tree.root,'Public state Merkle root mismatch.');
  check(Array.isArray(state.nullifiers??state.spentNullifiers),'Public state nullifier array required.');
  const nullifiers=(state.nullifiers??state.spentNullifiers).map(v=>String(field(v,FIELD-1n,true)));
  check(new Set(nullifiers).size===nullifiers.length,'Duplicate public nullifiers.');
  return {tree,spent:new Set(nullifiers)};
}
export function recoverAccount(account, profile, state) {
  accountSeed(account);
  const {tree,spent}=publicState(state,profile),secret=spendingSecret(account,profile),ownPub=poseidon([secret]),notes=new Map();
  const p=normalizeProfile(profile);
  const other=[];
  for(const text of account.notes) {
    check(typeof text==='string' && text.length<=2048,'Invalid saved note.');
    let record; try {record=JSON.parse(text);} catch {throw new Error('Invalid saved note JSON.');}
    if(record?.chainId!==p.chainId || record.pool!==p.pool) {other.push(text);continue;}
    const note=deserializeNote(text,profile);
    check(note.ownerPublicKey===ownPub,'Saved note is not owned by this account.'); notes.set(String(note.commitment),note);
  }
  const receipts=state.receipts??state.outputs;
  check(Array.isArray(receipts) && receipts.length<=2**TREE_DEPTH,'Public encrypted outputs required.');
  const seen=new Set(); let received=0;
  for(const event of receipts) {
    check(event && Number.isSafeInteger(event.index) && event.index>=0 && event.index<tree.leaves.length,'Invalid public output index.');
    const commitment=field(event.commitment,FIELD-1n,true),cipher=event.encryptedOutput;
    check(tree.leaves[event.index]===commitment && !seen.has(event.index),'Public output is missing, reordered or duplicated.');seen.add(event.index);
    bytes(cipher,RECEIPT_BYTES);
    let note;
    // Unauthenticated ciphertext belongs to another receiver or is unspendable.
    // It must never prevent recovery of independently valid owned outputs.
    try {note=bytes(cipher,RECEIPT_BYTES)[0]===2?decryptDynamicReceipt(account,profile,event):decryptReceipt(account,profile,commitment,cipher);} catch {continue;}
    if(!notes.has(String(commitment))) received++;
    notes.set(String(commitment),note);
  }
  check(other.length+notes.size<=MAX_NOTES,'Wallet note capacity exceeded.');
  account.notes=[...other,...[...notes.values()].map(note=>serializeNote(note,profile))];
  const leafSet=new Set(tree.leaves.map(String));
  const available=[...notes.values()].filter(note=>note.value>0n && leafSet.has(String(note.commitment)) && !spent.has(String(nullifier(note,secret,profile))));
  return {notes:available,balance:available.reduce((sum,note)=>sum+note.value,0n),received,root:tree.root};
}
export function selectNotes(notes, amount) {
  const target=field(amount,MAX_VALUE,true);
  check(Array.isArray(notes) && notes.length<=MAX_NOTES,'Invalid note-selection collection.');
  const items=notes.filter(note=>field(note.value,MAX_VALUE)>0n).map(note=>({...note,value:field(note.value,MAX_VALUE),commitment:field(note.commitment,FIELD-1n,true)}));
  check(new Set(items.map(n=>String(n.commitment))).size===items.length,'Duplicate note-selection inputs.');
  items.sort((a,b)=>a.value<b.value?-1:a.value>b.value?1:a.commitment<b.commitment?-1:1);
  let best=null,total;
  function consider(selected) {
    const sum=selected.reduce((n,note)=>n+note.value,0n);
    if(sum>=target && (!best || sum<total || sum===total && selected.length<best.length)) {best=selected;total=sum;}
  }
  for(const note of items) consider([note]);
  // Sorted two-pointer search finds the least total at or above target in O(n).
  let left=0,right=items.length-1;
  while(left<right) { const sum=items[left].value+items[right].value; if(sum>=target) {consider([items[left],items[right]]);right--;} else left++; }
  if(!best) {
    check(items.reduce((sum,note)=>sum+note.value,0n)<target,'Payment requires more than two inputs; consolidate notes first.');
    throw new Error('Insufficient private balance.');
  }
  return best;
}
function normalizeExtData(externalData) {
  exactKeys(externalData,['recipient','feeRecipient','processor','publicIn','publicOut','fee'],'external data');
  const ext={recipient:address(externalData.recipient,'recipient'),feeRecipient:address(externalData.feeRecipient,'fee recipient'),processor:address(externalData.processor,'processor'),publicIn:field(externalData.publicIn,MAX_VALUE),publicOut:field(externalData.publicOut,MAX_VALUE),fee:field(externalData.fee,MAX_VALUE)};
  check(ext.fee<=ext.publicOut,'Relayer fee exceeds public output.');
  check(ext.publicIn===0n || ext.publicOut===0n,'Simultaneous public deposit and withdrawal unsupported.');
  check(ext.publicOut===ext.fee || ext.recipient!==NATIVE_ASSET,'Withdrawal recipient is zero.');
  check(ext.fee===0n || ext.feeRecipient!==NATIVE_ASSET,'Fee recipient is zero.');
  return ext;
}
export function associationLeaf(commitment,profile) {
  return poseidon([field(commitment,FIELD-1n,true),normalizeProfile(profile).scope]);
}
function associationLeaves(leaves) {
  check(Array.isArray(leaves) && leaves.length<=2**TREE_DEPTH,'Invalid association-set leaf count.');
  const result=leaves.map(value=>field(value,FIELD-1n,true));
  check(new Set(result.map(String)).size===result.length,'Duplicate association-set leaves.');return result;
}
export function associationSetDigest(leaves) {
  return keccak256(encodeAbiParameters([{type:'uint256[]'}],[associationLeaves(leaves)]));
}
export function buildAssociationSet({commitments,profile}) {
  check(Array.isArray(commitments),'Association commitments required.');
  const leaves=associationLeaves(commitments.map(commitment=>associationLeaf(commitment,profile)));
  return {leaves:leaves.map(String),root:String(buildMerkleTree(leaves).root),digest:associationSetDigest(leaves)};
}
function aspPolicy(aspState,{requireLeaves=false}={}) {
  check(aspState && typeof aspState==='object','ASP policy required.');
  const root=field(aspState.root,FIELD-1n,true),epoch=field(aspState.epoch,(1n<<64n)-1n,true),validUntil=field(aspState.validUntil,(1n<<64n)-1n,true);
  let tree=null;
  if(requireLeaves || aspState.leaves!==undefined && aspState.leaves!==null) {
    const leaves=associationLeaves(aspState.leaves);tree=buildMerkleTree(leaves);
    check(tree.root===root,'Association-set root mismatch.');
    if(aspState.cidDigest!==undefined)check(associationSetDigest(leaves).toLowerCase()===aspState.cidDigest.toLowerCase(),'Association-set digest mismatch.');
  }
  return {root,epoch,validUntil,tree};
}
export function joinSplitContextBase(profile, externalData, encryptedOutputs) {
  const p=normalizeProfile(profile),ext=normalizeExtData(externalData);
  check(Array.isArray(encryptedOutputs) && encryptedOutputs.length===2,'Exactly two encrypted outputs required.');
  encryptedOutputs.forEach(cipher=>bytes(cipher,RECEIPT_BYTES));
  return BigInt(keccak256(encodeAbiParameters([
    {type:'bytes32'},{type:'uint256'},{type:'address'},{type:'uint256'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},
    {type:'uint128'},{type:'uint128'},{type:'uint128'},{type:'bytes32'},{type:'bytes32'},
  ],[DOMAIN,BigInt(p.chainId),p.pool,p.scope,p.registry,p.provider,ext.processor,ext.recipient,ext.feeRecipient,ext.publicIn,ext.publicOut,ext.fee,...encryptedOutputs.map(keccak256)])))%FIELD;
}
export function joinSplitContext(profile,externalData,encryptedOutputs,aspState) {
  const p=aspPolicy(aspState);
  return poseidon([joinSplitContextBase(profile,externalData,encryptedOutputs),poseidon([p.root,p.epoch,p.validUntil])]);
}
export function prepareJoinSplit({account,profile,state,aspState=state?.asp,inputs,outputs=[],externalData,extData}) {
  accountSeed(account);
  const {tree,spent}=publicState(state,profile),ext=normalizeExtData(externalData??extData),secret=spendingSecret(account,profile),self=receiverAddress(account,profile);
  check(ext.publicIn===0n,'ASP funding must use depositDynamic.');
  const policy=aspPolicy(aspState,{requireLeaves:true}),approved=new Set(policy.tree.leaves.map(String));
  // spendable is false when the latest policy is revoked or the provider rotated.
  check(aspState.spendable!==false,'ASP policy is revoked or the provider changed.');
  check(aspState.expired!==true && (state.blockTimestamp===undefined || policy.validUntil>field(state.blockTimestamp,(1n<<64n)-1n)),'ASP policy has expired.');
  check(aspState.acceptedUntil===undefined||state.blockTimestamp===undefined
    ||field(aspState.acceptedUntil,(1n<<64n)-1n)>field(state.blockTimestamp,(1n<<64n)-1n),'ASP policy grace period has expired.');
  check(Array.isArray(outputs) && outputs.length<=2,'At most two output specifications allowed.');
  const requested=outputs.map(output=>{
    exactKeys(output,['receiver','value'],'output specification');
    validateReceiver(output.receiver,profile);return {receiver:output.receiver,value:field(output.value,MAX_VALUE,true)};
  });
  const outputTotal=requested.reduce((sum,output)=>sum+output.value,0n),target=outputTotal+ext.publicOut;
  check(target<=MAX_VALUE,'Requested public and private output total exceeds uint128.');
  if(inputs===undefined) {
    const recovered=recoverAccount(structuredClone(account),profile,state);
    inputs=target>ext.publicIn?selectNotes(recovered.notes.filter(note=>approved.has(String(associationLeaf(note.commitment,profile)))),target-ext.publicIn):[];
  }
  check(Array.isArray(inputs) && inputs.length<=2,'JoinSplit supports at most two real inputs.');
  const inputNotes=inputs.map(note=>normalizeNote(note,profile));
  check(new Set(inputNotes.map(note=>String(note.commitment))).size===inputNotes.length,'Duplicate JoinSplit inputs.');
  const witnesses=[];
  for(const note of inputNotes) {
    check(note.value>0n,'Explicit real input must have nonzero value.');
    const nf=nullifier(note,secret,profile);
    check(!spent.has(String(nf)),'Input note has already been spent.');
    const index=tree.leaves.findIndex(value=>value===note.commitment);
    check(index>=0,'Input note is not in the public Merkle tree.');
    const aspIndex=policy.tree.leaves.findIndex(value=>value===associationLeaf(note.commitment,profile));
    check(aspIndex>=0,'Input note is pending ASP approval.');
    const aspProof=policy.tree.generateProof(aspIndex);
    witnesses.push({note,secret,nf,...tree.generateProof(index),aspIndex,aspSiblings:aspProof.siblings});
  }
  const inputTotal=inputNotes.reduce((sum,note)=>sum+note.value,0n)+ext.publicIn;
  check(inputTotal<=MAX_VALUE && inputTotal>=target,'JoinSplit value conservation failed.');
  const change=inputTotal-target;
  if(change>0n) {check(requested.length<2,'Two recipient outputs leave no slot for change.');requested.push({receiver:self,value:change});}
  while(witnesses.length<2) {
    const dummySecret=randomField(),dummyPub=poseidon([dummySecret]),blinding=randomField(),commitment=poseidon([0n,poseidon([dummyPub,blinding])]);
    const note={value:0n,blinding,commitment};
    witnesses.push({note,secret:dummySecret,nf:poseidon([dummySecret,commitment,normalizeProfile(profile).scope]),index:0,siblings:Array(TREE_DEPTH).fill(0n),aspIndex:0,aspSiblings:Array(TREE_DEPTH).fill(0n)});
  }
  while(requested.length<2) requested.push({receiver:self,value:0n});
  const outputNotes=requested.map(output=>createNote(output,profile));
  check(ext.publicIn>0n || ext.publicOut>0n || outputNotes.some(note=>note.value>0n),'Empty JoinSplit transaction is not permitted.');
  const positiveCommitments=outputNotes.filter(note=>note.value>0n).map(note=>String(note.commitment));
  check(new Set(positiveCommitments).size===positiveCommitments.length,'Duplicate output commitments.');
  const encryptedOutputs=outputNotes.map((note,index)=>encryptReceipt(requested[index].receiver,note,profile));
  const contextBase=joinSplitContextBase(profile,ext,encryptedOutputs),context=joinSplitContext(profile,ext,encryptedOutputs,aspState),scope=normalizeProfile(profile).scope;
  const inputSignals={root:tree.root,publicIn:ext.publicIn,publicOut:ext.publicOut,context,scope,contextBase,aspRoot:policy.root,aspEpoch:policy.epoch,aspValidUntil:policy.validUntil,
    inputNullifiers:witnesses.map(w=>w.nf),outputCommitments:outputNotes.map(n=>n.commitment),
    inputValues:witnesses.map(w=>w.note.value),inputSecrets:witnesses.map(w=>w.secret),inputBlindings:witnesses.map(w=>w.note.blinding),
    inputPathIndices:witnesses.map(w=>BigInt(w.index)),inputPathElements:witnesses.map(w=>w.siblings),
    inputASPPathIndices:witnesses.map(w=>BigInt(w.aspIndex)),inputASPPathElements:witnesses.map(w=>w.aspSiblings),
    outputValues:outputNotes.map(n=>n.value),outputPubKeys:outputNotes.map(n=>n.ownerPublicKey),outputBlindings:outputNotes.map(n=>n.blinding)};
  const publicSignals=[tree.root,ext.publicIn,ext.publicOut,context,scope,...inputSignals.inputNullifiers,...inputSignals.outputCommitments].map(String);
  // Preparation itself does not publish notes or mutate the encrypted backup.
  return {inputSignals,publicSignals,extData:ext,encryptedOutputs,outputNotes,inputNotes};
}
export const SWAP_DOMAIN=keccak256(stringToHex('CHENG_PHASE2_ROUTES_V1'));
export const MAX_ROUTE_HOPS=4;
function routeProtocol(value) {
  if(value===0 || value==='Uniswap V3')return {id:0,name:'Uniswap V3'};
  if(value===1 || value==='UP Slipstream')return {id:1,name:'UP Slipstream'};
  throw new Error('Unsupported routed swap protocol.');
}
export function normalizeSwapRoute({sourceProfile,targetProfile,route}) {
  const source=normalizeProfile(sourceProfile),target=normalizeProfile(targetProfile);
  check(source.chainId===target.chainId && source.pool!==target.pool,'Swap pools must differ on the same chain.');
  check(route && typeof route==='object','Immutable swap route required.');
  const normalized=Object.fromEntries(['adapter','router','wrappedNative','factory'].map(name=>[name,address(route[name],name,true)]));
  check(new Set(Object.values(normalized)).size===4,'Swap route roles must differ.');
  for(const [name,expected] of [['sourcePool',source.pool],['targetPool',target.pool]])if(route[name]!==undefined)check(address(route[name],name,true)===expected,'Swap route pool mismatch.');
  const protocol=routeProtocol(route.protocol),encoded=route.path;
  check(typeof encoded==='string' && /^0x[0-9a-f]+$/i.test(encoded),'Invalid packed route path.');
  const body=encoded.slice(2),length=body.length/2,hops=(length-20)/23;
  check(Number.isSafeInteger(hops) && hops>=1 && hops<=MAX_ROUTE_HOPS,'Route requires one to four hops.');
  const tokens=[address(`0x${body.slice(0,40)}`,'route token',true)],parameters=[];
  for(let i=0;i<hops;i++) {
    const offset=40+i*46,parameter=Number.parseInt(body.slice(offset,offset+6),16);
    check(parameter>0 && parameter<(protocol.id===0?1_000_000:1<<23),'Invalid route fee or tick spacing.');
    parameters.push(parameter);tokens.push(address(`0x${body.slice(offset+6,offset+46)}`,'route token',true));
  }
  check(new Set(tokens).size===tokens.length,'Repeated route token.');
  const tokenIn=source.asset===NATIVE_ASSET?normalized.wrappedNative:source.asset,tokenOut=target.asset===NATIVE_ASSET?normalized.wrappedNative:target.asset;
  check(tokens[0]===tokenIn && tokens.at(-1)===tokenOut,'Route path asset endpoints mismatch.');
  return {...normalized,chainId:source.chainId,sourcePool:source.pool,targetPool:target.pool,sourceAsset:source.asset,targetAsset:target.asset,
    protocol:protocol.id,protocolName:protocol.name,path:encoded.toLowerCase(),pathHash:keccak256(encoded),tokens,parameters,hops,
    wrapNative:source.asset===NATIVE_ASSET,unwrapNative:target.asset===NATIVE_ASSET};
}
export function normalizeSwapAction(action) {
  exactKeys(action,['processor','amountIn','minAmountOut','deadline','targetPrecommitment','encryptedTemplate'],'swap action');
  const result={processor:address(action.processor,'swap submitter',true),amountIn:field(action.amountIn,MAX_VALUE,true),minAmountOut:field(action.minAmountOut,MAX_VALUE,true),
    deadline:field(action.deadline,(1n<<256n)-1n,true),targetPrecommitment:field(action.targetPrecommitment,FIELD-1n,true),encryptedTemplate:action.encryptedTemplate};
  check(bytes(result.encryptedTemplate,RECEIPT_BYTES)[0]===2,'Dynamic receiver template required.');
  return result;
}
export function swapActionHash({sourceProfile,targetProfile,route,action}) {
  const r=normalizeSwapRoute({sourceProfile,targetProfile,route}),a=normalizeSwapAction(action);
  return keccak256(encodeAbiParameters([
    {type:'bytes32'},{type:'uint256'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},{type:'address'},
    {type:'uint8'},{type:'bytes32'},{type:'address'},{type:'uint128'},{type:'uint128'},{type:'uint256'},{type:'uint256'},{type:'bytes32'},
  ],[SWAP_DOMAIN,BigInt(r.chainId),r.adapter,r.sourcePool,r.targetPool,r.router,r.wrappedNative,r.factory, r.protocol,r.pathHash,
    a.processor,a.amountIn,a.minAmountOut,a.deadline,a.targetPrecommitment,keccak256(a.encryptedTemplate)]));
}
export function swapActionEnvelope(options) { return `${swapActionHash(options)}${'00'.repeat(224)}`; }
/** Builds a source proof and a bound target invoice without predicting DEX output. */
export function prepareSwap({account,sourceProfile,targetProfile,sourceState,route,action,inputs,receiver}) {
  const r=normalizeSwapRoute({sourceProfile,targetProfile,route});
  check(action && typeof action==='object','Swap action required.');
  let selected={...action};
  if(selected.targetPrecommitment===undefined && selected.encryptedTemplate===undefined) {
    const invoice=receiver?.precommitment!==undefined?receiver:receiver?createDynamicReceiver(receiver,targetProfile):createDynamicReceive(account,targetProfile);
    selected={...selected,targetPrecommitment:invoice.precommitment,encryptedTemplate:invoice.encryptedTemplate};
  }
  const a=normalizeSwapAction(selected),prepared=prepareJoinSplit({account,profile:sourceProfile,state:sourceState,inputs,outputs:[],externalData:{
    recipient:r.adapter,feeRecipient:NATIVE_ASSET,processor:r.adapter,publicIn:0n,publicOut:a.amountIn,fee:0n,
  }});
  check(prepared.outputNotes[1].commitment===0n,'Swap action requires the second source output to be empty.');
  const options={sourceProfile,targetProfile,route,action:a},actionHash=swapActionHash(options),actionEnvelope=swapActionEnvelope(options);
  prepared.encryptedOutputs[1]=actionEnvelope;
  const context=joinSplitContext(sourceProfile,prepared.extData,prepared.encryptedOutputs,sourceState.asp);
  prepared.inputSignals.contextBase=joinSplitContextBase(sourceProfile,prepared.extData,prepared.encryptedOutputs);
  prepared.inputSignals.context=context;prepared.publicSignals[3]=String(context);
  return {...prepared,action:a,actionHash,actionEnvelope,route:r};
}
export function publicTransaction(prepared, proof) {
  check(prepared && Array.isArray(prepared.publicSignals) && prepared.publicSignals.length===9,'Invalid prepared JoinSplit.');
  const signals=prepared.publicSignals.map(v=>String(field(v)));
  const ext=normalizeExtData(prepared.extData);
  check(Array.isArray(prepared.encryptedOutputs) && prepared.encryptedOutputs.length===2,'Invalid encrypted outputs.');
  prepared.encryptedOutputs.forEach(cipher=>bytes(cipher,RECEIPT_BYTES));
  check(proof && typeof proof==='object','Groth16 proof required.');
  const p = proof.pA ? {a:proof.pA,b:proof.pB,c:proof.pC} : proof.a ? proof : Array.isArray(proof) && proof.length===3 ? {a:proof[0],b:proof[1],c:proof[2]} : {a:[proof.pi_a?.[0],proof.pi_a?.[1]],b:[[proof.pi_b?.[0]?.[1],proof.pi_b?.[0]?.[0]],[proof.pi_b?.[1]?.[1],proof.pi_b?.[1]?.[0]]],c:[proof.pi_c?.[0],proof.pi_c?.[1]]};
  const BASE_FIELD=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  check(Array.isArray(p.a)&&p.a.length===2&&Array.isArray(p.b)&&p.b.length===2&&p.b.every(row=>Array.isArray(row)&&row.length===2)&&Array.isArray(p.c)&&p.c.length===2,'Invalid Groth16 proof coordinates.');
  return {pA:p.a.map(v=>String(field(v,BASE_FIELD-1n))),pB:p.b.map(row=>row.map(v=>String(field(v,BASE_FIELD-1n)))),pC:p.c.map(v=>String(field(v,BASE_FIELD-1n))),pubSignals:signals,
    extData:Object.fromEntries(Object.entries(ext).map(([key,value])=>[key,typeof value==='bigint'?String(value):value])),encryptedOutputs:[...prepared.encryptedOutputs]};
}
export const EXIT_DOMAIN=keccak256(stringToHex('CHENG_PHASE2_ASP_EXIT_V1'));
function normalizeExitData(data) {
  exactKeys(data,['processor','recipient','feeRecipient','fee'],'holder-exit data');
  const result={processor:address(data.processor,'exit processor',true),recipient:address(data.recipient,'exit recipient',true),feeRecipient:address(data.feeRecipient,'exit fee recipient'),fee:field(data.fee,MAX_VALUE)};
  check(result.fee===0n || result.feeRecipient!==NATIVE_ASSET,'Exit fee recipient is zero.');return result;
}
export function holderExitContext(profile,externalData) {
  const p=normalizeProfile(profile),data=normalizeExitData(externalData);
  return BigInt(keccak256(encodeAbiParameters([
    {type:'bytes32'},{type:'uint256'},{type:'address'},{type:'uint256'},{type:'address'},{type:'address'},{type:'address'},{type:'uint128'},
  ],[EXIT_DOMAIN,BigInt(p.chainId),p.pool,p.scope,data.processor,data.recipient,data.feeRecipient,data.fee])))%FIELD;
}
export function prepareHolderExit({account,profile,note,state,externalData,extData}) {
  accountSeed(account);
  const n=normalizeNote(note,profile),secret=spendingSecret(account,profile),nf=nullifier(n,secret,profile),data=normalizeExitData(externalData??extData),scope=normalizeProfile(profile).scope;
  check(n.value>0n && data.fee<=n.value,'Invalid holder-exit amount or fee.');
  check(data.recipient!==normalizeProfile(profile).pool && (data.fee===0n || data.feeRecipient!==normalizeProfile(profile).pool),'Exit cannot pay the pool itself.');
  if(state) {
    const {tree,spent}=publicState(state,profile);
    check(tree.leaves.includes(n.commitment),'Exit note is absent from canonical pool state.');
    check(!spent.has(String(nf)),'Exit note has already been spent.');
  }
  const context=holderExitContext(profile,data),inputSignals={commitment:n.commitment,nullifier:nf,value:n.value,scope,context,secret,blinding:n.blinding};
  return {inputSignals,publicSignals:[n.commitment,nf,n.value,scope,context].map(String),data,extData:data,note:n};
}
export function prepareRagequit(options) {
  const {profile,note,state}=options;
  accountSeed(options.account);
  const n=normalizeNote(note,profile);
  nullifier(n,spendingSecret(options.account,profile),profile);
  check(state && Array.isArray(state.deposits),'Canonical original-deposit records required for ragequit.');
  const record=state.deposits.find(record=>String(record.commitment)===String(n.commitment));
  check(record && field(record.value,MAX_VALUE,true)===n.value,'Note has no canonical original-deposit record.');
  const originalDepositor=address(record.originalDepositor??record.processor,'original depositor',true);
  const supplied=options.externalData??options.extData??{processor:options.processor,recipient:originalDepositor,feeRecipient:NATIVE_ASSET,fee:0n};
  const data=normalizeExitData(supplied);
  check(data.recipient===originalDepositor && data.fee===0n && data.feeRecipient===NATIVE_ASSET,'Ragequit must return the entire original deposit with zero fee.');
  return {...prepareHolderExit({...options,externalData:data}),ragequit:true,originalDepositor};
}
export function publicHolderExitTransaction(prepared,proof) {
  check(Array.isArray(prepared?.publicSignals) && prepared.publicSignals.length===5,'Prepared five-signal holder exit required.');
  // Reuse the same proof coordinate normalization without exposing a witness.
  const dummy={publicSignals:[...prepared.publicSignals,'0','0','0','0'],extData:{recipient:NATIVE_ASSET,feeRecipient:NATIVE_ASSET,processor:NATIVE_ASSET,publicIn:0n,publicOut:0n,fee:0n},encryptedOutputs:[`0x${'00'.repeat(RECEIPT_BYTES)}`,`0x${'00'.repeat(RECEIPT_BYTES)}`]};
  const {pA,pB,pC}=publicTransaction(dummy,proof),data=normalizeExitData(prepared.data??prepared.extData);
  return {pA,pB,pC,pubSignals:prepared.publicSignals.map(value=>String(field(value))),data:Object.fromEntries(Object.entries(data).map(([key,value])=>[key,typeof value==='bigint'?String(value):value]))};
}
export const publicHolderExit=publicHolderExitTransaction;
export function rememberOutputs(account,profile,prepared) {
  accountSeed(account);const own=field(receiverAddress(account,profile).ownerPublicKey),notes=new Map(account.notes.map(text=>[text,text]));
  for(const output of prepared.outputNotes??[]) {const note=normalizeNote(output,profile);if(note.value>0n && note.ownerPublicKey===own) {const text=serializeNote(note,profile);notes.set(text,text);}}
  check(notes.size<=MAX_NOTES,'Wallet note capacity exceeded.');account.notes=[...notes.values()];
}
function passwordCheck(password) {check(typeof password==='string' && Buffer.byteLength(password,'utf8')>=16 && Buffer.byteLength(password,'utf8')<=1024,'Backup password length must be 16–1024 bytes.');}
const backupAAD=Buffer.from('CHENG_PHASE2_ASP_ENCRYPTED_ACCOUNT_V1');
export function sealAccount(account,password) {
  passwordCheck(password);accountSeed(account);
  exactKeys(account,['version','seed','notes'],'account');
  const plain=Buffer.from(JSON.stringify(account));check(plain.length<=MAX_BACKUP_BYTES,'Account backup too large.');
  const salt=randomBytes(32),iv=randomBytes(12),key=scryptSync(password,salt,32,{N:BACKUP_N,r:BACKUP_R,p:BACKUP_P,maxmem:64*1024*1024});
  const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(backupAAD);
  return {schema:'phase2-asp-encrypted-account/v1',kdf:'scrypt',N:BACKUP_N,r:BACKUP_R,p:BACKUP_P,salt:hex(salt),iv:hex(iv),ciphertext:hex(Buffer.concat([cipher.update(plain),cipher.final()])),tag:hex(cipher.getAuthTag())};
}
export function openAccount(envelope,password) {
  passwordCheck(password);
  exactKeys(envelope,['schema','kdf','N','r','p','salt','iv','ciphertext','tag'],'backup');
  check(envelope.schema==='phase2-asp-encrypted-account/v1' && envelope.kdf==='scrypt' && envelope.N===BACKUP_N && envelope.r===BACKUP_R && envelope.p===BACKUP_P,'Unsupported backup KDF parameters.');
  check(typeof envelope.ciphertext==='string' && envelope.ciphertext.length<=MAX_BACKUP_BYTES*2+2 && /^0x(?:[0-9a-f]{2})+$/i.test(envelope.ciphertext),'Invalid backup ciphertext size.');
  const salt=bytes(envelope.salt,32),iv=bytes(envelope.iv,12),tag=bytes(envelope.tag,16),ciphertext=Buffer.from(envelope.ciphertext.slice(2),'hex');
  const key=scryptSync(password,salt,32,{N:BACKUP_N,r:BACKUP_R,p:BACKUP_P,maxmem:64*1024*1024}),decipher=createDecipheriv('aes-256-gcm',key,iv);
  decipher.setAAD(backupAAD);decipher.setAuthTag(tag);
  let account;try {account=JSON.parse(Buffer.concat([decipher.update(ciphertext),decipher.final()]).toString('utf8'));} catch {throw new Error('Backup authentication failed.');}
  exactKeys(account,['version','seed','notes'],'account');accountSeed(account);
  check(account.notes.every(note=>typeof note==='string' && note.length<=2048),'Invalid backup note collection.');return account;
}
export async function writeBackup(filename,account,password) {
  check(path.isAbsolute(filename),'Absolute backup path required.');
  const directory=path.dirname(filename),stat=await fs.lstat(directory);
  check(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0 && await fs.realpath(directory)===directory,'Private non-symlink backup directory with mode 0700 required.');
  const envelope=sealAccount(account,password),handle=await fs.open(filename,fsConstants.O_WRONLY|fsConstants.O_CREAT|fsConstants.O_EXCL|fsConstants.O_NOFOLLOW,0o600);
  try {await handle.writeFile(JSON.stringify(envelope));await handle.sync();} finally {await handle.close();}
  return filename;
}
export async function readBackup(filename,password) {
  check(path.isAbsolute(filename),'Absolute backup path required.');
  const directory=path.dirname(filename),directoryStat=await fs.lstat(directory);
  check(directoryStat.isDirectory()&&!directoryStat.isSymbolicLink()&&(directoryStat.mode&0o077)===0 && await fs.realpath(directory)===directory,'Private non-symlink backup directory with mode 0700 required.');
  const handle=await fs.open(filename,fsConstants.O_RDONLY|fsConstants.O_NOFOLLOW);
  try {const stat=await handle.stat();check(stat.isFile()&&(stat.mode&0o077)===0&&stat.size<=MAX_BACKUP_BYTES*2+4096,'Private regular backup file with mode 0600 required.');return openAccount(JSON.parse(await handle.readFile('utf8')),password);} finally {await handle.close();}
}
export async function verifyCircuitArtifacts({rootDirectory=ROOT,expectedManifestSHA256,circuit='joinsplit'}={}) {
  check(['joinsplit','holder-exit'].includes(circuit),'Unsupported ASP circuit.');
  check(path.isAbsolute(rootDirectory) && await fs.realpath(rootDirectory)===rootDirectory,'Canonical circuit root directory required.');
  const relativeManifest=`artifacts/phase2-asp/circuits/${circuit}/manifest.json`,publicCount=circuit==='holder-exit'?5:9;
  async function read(relative,expected) {
    check(typeof relative==='string' && !path.isAbsolute(relative) && !relative.split('/').includes('..'),'Unsafe circuit artifact path.');
    const filename=path.resolve(rootDirectory,relative),stat=await fs.lstat(filename);
    check(filename.startsWith(rootDirectory+path.sep) && stat.isFile() && !stat.isSymbolicLink() && await fs.realpath(filename)===filename,'Regular non-symlink circuit artifact required.');
    const data=await fs.readFile(filename);
    if(expected)check(stat.size===expected.bytes && sha(data).toString('hex')===expected.sha256,'Circuit artifact hash mismatch.');
    return {filename,data};
  }
  const {data:manifestBytes}=await read(relativeManifest);
  if(expectedManifestSHA256!==undefined)check(/^[a-f0-9]{64}$/.test(expectedManifestSHA256) && sha(manifestBytes).toString('hex')===expectedManifestSHA256,'Circuit manifest hash mismatch.');
  const manifest=JSON.parse(manifestBytes);
  check(manifest.schema==='phase2-asp-dev-circuits/v1' && manifest.testOnly===true && manifest.productionReady===false && manifest.officialFinalKey===false && manifest.protocol==='groth16' && manifest.curve==='bn128','Unsupported or falsely production-ready circuit manifest.');
  check(JSON.stringify(manifest.allowedChainIds)==='[31341,46630]' && manifest.inputs?.circuit===circuit && manifest.inputs?.maxTreeDepth===(circuit==='holder-exit'?null:TREE_DEPTH) && manifest.counts?.publicInputs===publicCount && manifest.counts?.outputs===0,'ASP circuit public interface mismatch.');
  check(manifest.setup?.verifyFromR1cs===true && manifest.setup?.officialCeremony===false && manifest.setup?.kind==='self-generated-test-development-phase2','Development proving key verification missing.');
  const expectedSources=circuit==='holder-exit'?['protocol/phase2-asp/circuits/holder-exit/main.circom']:['protocol/phase2-asp/circuits/joinsplit/joinsplit.circom','protocol/phase2-asp/circuits/joinsplit/main.circom'];
  check(Array.isArray(manifest.inputs.sources) && manifest.inputs.sources.length===expectedSources.length && sha(Buffer.from(JSON.stringify(manifest.inputs.sources))).toString('hex')===manifest.inputs.sourceSetSHA256,'Circuit source inventory hash mismatch.');
  check(manifest.inputs.sources.every((source,index)=>source.path===expectedSources[index]),'Unexpected ASP circuit source set.');
  for(const source of manifest.inputs.sources)await read(source.path,source);
  const files={};
  for(const [name,suffix] of [['wasm',`${circuit}.wasm`],['zkey',`${circuit}.dev.zkey`],['vkey',`${circuit}.vkey.json`],['r1cs',`${circuit}.r1cs`]]) {
    const descriptor=manifest.artifacts?.[name];
    check(descriptor?.path===`artifacts/phase2-asp/circuits/${circuit}/${suffix}` && Number.isSafeInteger(descriptor.bytes) && descriptor.bytes>0 && /^[a-f0-9]{64}$/.test(descriptor.sha256),'Unexpected circuit artifact descriptor.');
    files[name]=await read(descriptor.path,descriptor);
  }
  const vkey=JSON.parse(files.vkey.data);
  check(vkey.protocol==='groth16' && vkey.curve==='bn128' && vkey.nPublic===publicCount && Array.isArray(vkey.IC) && vkey.IC.length===publicCount+1,'Verification key public input mismatch.');
  return {manifest,manifestSHA256:sha(manifestBytes).toString('hex'),wasm:files.wasm.filename,zkey:files.zkey.filename,vkey};
}
async function provePrepared(prepared,options,circuit) {
  const signalCount=circuit==='holder-exit'?5:9;
  check(Array.isArray(prepared?.publicSignals) && prepared.publicSignals.length===signalCount && prepared.inputSignals,'Prepared private witness required.');
  let artifacts;
  if(options.productionProfile){
    const p=normalizeProfile(options.productionProfile);check(p.chainId===4663 && String(prepared.publicSignals[circuit==='holder-exit'?3:4])===String(p.scope),'Production proof belongs to another pool.');
    const {loadProductionRelease}=await import('../phase2-mainnet/artifacts.mjs');
    const release=await loadProductionRelease({rootDirectory:options.rootDirectory??ROOT,profile:options.productionProfile}),final=release.circuits[circuit];
    artifacts={manifest:final.manifest,manifestSHA256:final.manifestSHA256,wasm:final.files.wasm.absolute,zkey:final.files.zkey.absolute,vkey:JSON.parse(final.files.vkey.bytes.toString('utf8'))};
  }else artifacts=await verifyCircuitArtifacts({...options,circuit});
  // The prover receives a witness through stdin, never argv or a plaintext file.
  // A short-lived child also releases snarkjs worker pools reliably on Node 26.
  const code=`import * as snarkjs from 'snarkjs';
let input='';for await(const chunk of process.stdin) input+=chunk;
try {const {witness,wasm,zkey,vkey}=JSON.parse(input);
const result=await snarkjs.groth16.fullProve(witness,wasm,zkey,undefined,undefined,{singleThread:true});
if(!await snarkjs.groth16.verify(vkey,result.publicSignals,result.proof)) process.exit(2);
process.stdout.write(JSON.stringify(result));process.exit(0);
}catch{process.exit(1);}`;
  const result=await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--input-type=module','-e',code],{cwd:options.rootDirectory??ROOT,stdio:['pipe','pipe','ignore']});
    let stdout='',failed=false;
    const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');reject(new Error('Local proof generation timed out.'));},120000);
    child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>1024*1024){failed=true;child.kill('SIGKILL');clearTimeout(timer);reject(new Error('Unexpected prover output size.'));}});
    child.on('error',()=>{clearTimeout(timer);if(!failed)reject(new Error('Unable to start local proof worker.'));});
    child.on('close',exitCode=>{clearTimeout(timer);if(failed)return;if(exitCode!==0){reject(new Error('Local proof generation or verification failed.'));return;}
      try {resolve(JSON.parse(stdout));} catch {reject(new Error('Invalid local prover result.'));}});
    child.stdin.on('error',()=>{});
    child.stdin.end(JSON.stringify({witness:prepared.inputSignals,wasm:artifacts.wasm,zkey:artifacts.zkey,vkey:artifacts.vkey},(_,value)=>typeof value==='bigint'?String(value):value));
  });
  check(result.publicSignals.length===signalCount && result.publicSignals.every((value,index)=>String(value)===prepared.publicSignals[index]),'Prover returned unexpected public signals.');
  return {...result,transaction:circuit==='holder-exit'?publicHolderExitTransaction(prepared,result.proof):publicTransaction(prepared,result.proof),manifestSHA256:artifacts.manifestSHA256};
}

export function proveJoinSplit(prepared,options={}) {return provePrepared(prepared,options,'joinsplit');}
export function proveHolderExit(prepared,options={}) {return provePrepared(prepared,options,'holder-exit');}
