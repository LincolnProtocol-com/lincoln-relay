// SPDX-License-Identifier: Apache-2.0
// Shared testnet fee accounting. Reservations survive crashes and are never
// released merely because a transaction or HTTP response was not observed.
import fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {readCombinedTestnetFees} from '../phase1-service/signing.mjs';

// User-authorized cumulative testnet gas ceiling, including earlier versions.
const CAP=2100000000000000n,GENESIS='0x829a42e6d68c872aafcef3abb2123fe371138fc415dd8b44381bbbf23049dd32';
export const ASP_BUDGET_EXTENSION_CAP_WEI=100000000000000000n;
export const ASP_BUDGET_EXTENSION_AUTHORIZATION_PATH='artifacts/phase2-asp/testnet-budget-authorization-20261016-cloud-e2e.json';
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const shaBytes=v=>createHash('sha256').update(v).digest('hex');
const integer=v=>{check(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v),'INVALID_BUDGET_QUANTITY');return BigInt(v);};
const hash=v=>typeof v==='string'&&/^0x[0-9a-f]{64}$/i.test(v);
const wire=v=>JSON.parse(JSON.stringify(v,(_,x)=>typeof x==='bigint'?String(x):x));
async function read(filename,optional=false){
  let h;try{h=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);const s=await h.stat();check(s.isFile()&&(s.mode&0o022)===0&&s.size<16*1024*1024,'UNSAFE_BUDGET_FILE');return JSON.parse(await h.readFile('utf8'));}
  catch(e){if(optional&&e.code==='ENOENT')return null;throw e;}finally{await h?.close();}
}
async function atomic(filename,value){
  const tmp=`${filename}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,h=await fs.open(tmp,'wx',0o600);
  try{await h.writeFile(JSON.stringify(value,null,2)+'\n');await h.sync();}finally{await h.close();}
  try{await fs.rename(tmp,filename);const d=await fs.open(path.dirname(filename),'r');try{await d.sync();}finally{await d.close();}}
  finally{await fs.unlink(tmp).catch(e=>{if(e.code!=='ENOENT')throw e;});}
}
async function lock(filename){
  const token=randomBytes(16).toString('hex');let h;
  for(let i=0;i<100;i++){try{h=await fs.open(filename,'wx',0o600);break;}catch(e){if(e.code!=='EEXIST')throw e;check(i<99,'SHARED_TESTNET_BUDGET_LOCKED');await new Promise(r=>setTimeout(r,50));}}
  const s=await h.stat();await h.writeFile(JSON.stringify({pid:process.pid,token}));await h.sync();
  return async()=>{try{const current=await fs.lstat(filename),v=await read(filename);check(current.ino===s.ino&&v.token===token,'BUDGET_LOCK_CHANGED');await fs.unlink(filename);}finally{await h.close();}};
}
function validateJournal(journal,identity){
  check(journal?.schema==='phase2-asp-shared-fees/v1'&&journal.identity===identity&&journal.chainId===46630&&journal.genesisHash===GENESIS&&Array.isArray(journal.jobs)&&journal.jobs.length<=2048,'INVALID_ASP_BUDGET_JOURNAL');
  const ids=new Set(),nonces=new Set();
  for(const j of journal.jobs){
    check(typeof j.id==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(j.id)&&!ids.has(j.id)&&/^[a-f0-9]{64}$/.test(j.fingerprint),'INVALID_ASP_BUDGET_JOB');ids.add(j.id);
    check(typeof j.processor==='string'&&/^0x[0-9a-f]{40}$/.test(j.processor)&&Number.isSafeInteger(j.nonce)&&j.nonce>=0,'INVALID_BUDGET_SENDER');
    const key=`${j.processor}:${j.nonce}`;check(!nonces.has(key),'DUPLICATE_BUDGET_NONCE');nonces.add(key);
    check(integer(j.ceiling)>0n&&['reserved','settled'].includes(j.status),'INVALID_FEE_RESERVATION');
    check(typeof j.to==='string'&&/^0x[0-9a-f]{40}$/.test(j.to)&&typeof j.data==='string'&&/^0x(?:[0-9a-f]{2})*$/.test(j.data)
      &&integer(j.gas)>0n&&integer(j.gasPrice)>0n&&integer(j.gas)*integer(j.gasPrice)===integer(j.ceiling),'INVALID_RESERVED_TRANSACTION');integer(j.value);
    check(j.fingerprint===sha({processor:j.processor,nonce:j.nonce,chainId:46630,to:j.to,data:j.data,gas:j.gas,gasPrice:j.gasPrice,ceiling:j.ceiling,value:j.value}),'BUDGET_INTENT_DIGEST_MISMATCH');
    if(j.status==='settled')check(hash(j.hash)&&hash(j.blockHash)&&integer(j.fee)<=integer(j.ceiling),'INVALID_FEE_SETTLEMENT');
  }
  return journal;
}
const cost=journal=>journal.jobs.reduce((sum,j)=>sum+integer(j.status==='settled'?j.fee:j.ceiling),0n);

function extensionDescriptor(value){
  check(value&&Object.keys(value).sort().join(',')==='authorizationPath,authorizationSHA256,previousPolicySHA256'
    &&value.authorizationPath===ASP_BUDGET_EXTENSION_AUTHORIZATION_PATH
    &&/^[a-f0-9]{64}$/.test(value.authorizationSHA256)&&/^[a-f0-9]{64}$/.test(value.previousPolicySHA256),'INVALID_TESTNET_BUDGET_EXTENSION');
  return {authorizationPath:value.authorizationPath,authorizationSHA256:value.authorizationSHA256,previousPolicySHA256:value.previousPolicySHA256};
}

/** Pure builder shared with the explicit, stopped-writer policy transition CLI.
 * Building a policy grants no authorization and never updates a stored policy.
 */
export function createASPBudgetPolicy({profile,budgetWei=CAP,minimumCombinedFeeWei=0n,budgetExtension=null}){
  check(typeof budgetWei==='bigint'&&budgetWei>0n&&budgetWei<=ASP_BUDGET_EXTENSION_CAP_WEI
    &&typeof minimumCombinedFeeWei==='bigint'&&minimumCombinedFeeWei>=0n&&minimumCombinedFeeWei<=budgetWei,'INVALID_NARROW_TESTNET_BUDGET');
  const extended=budgetWei>CAP;
  check(extended?budgetWei===ASP_BUDGET_EXTENSION_CAP_WEI&&budgetExtension!==null:budgetExtension===null,'INVALID_NARROW_TESTNET_BUDGET');
  check(profile?.chain?.id===46630&&profile.genesisHash===GENESIS&&profile.testOnly===true&&profile.productionReady===false,'TESTNET_BUDGET_PROFILE_REQUIRED');
  const identity=sha({pool:profile.pool.address.toLowerCase(),artifact:profile.artifactSHA256,genesis:GENESIS});
  return {schema:'phase2-asp-budget-policy/v1',identity,chainId:46630,genesisHash:GENESIS,budgetWei:String(budgetWei),minimumCombinedFeeWei:String(minimumCombinedFeeWei),
    ...(extended?{budgetExtension:extensionDescriptor(budgetExtension)}:{})};
}

async function readPinnedExtensionFile(filename,expectedSHA256){
  const h=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const s=await h.stat();check(s.isFile()&&(s.mode&0o022)===0&&s.size<=65536&&await fs.realpath(filename)===filename,'UNSAFE_TESTNET_BUDGET_EXTENSION_FILE');
    const bytes=await h.readFile();check(shaBytes(bytes)===expectedSHA256,'TESTNET_BUDGET_EXTENSION_SHA256_MISMATCH');return JSON.parse(bytes.toString('utf8'));
  }finally{await h.close();}
}

/** Only a fixed, hash-pinned explicit approval can authorize the larger ceiling.
 * A pending placeholder, altered file or old approval remains insufficient.
 */
export async function readASPBudgetExtensionAuthorization({rootDirectory,budgetExtension}){
  const extension=extensionDescriptor(budgetExtension),root=path.resolve(rootDirectory);
  check(await fs.realpath(root)===root,'UNSAFE_TESTNET_BUDGET_EXTENSION_ROOT');
  const record=await readPinnedExtensionFile(path.join(root,extension.authorizationPath),extension.authorizationSHA256);
  check(record?.schema==='phase2-asp-testnet-budget-authorization/v1'&&record.chainId===46630&&record.genesisHash===GENESIS
    &&record.deployer?.toLowerCase()==='0x36437b878415eda1a24186cf79afffbc9eced298'&&record.testOnly===true&&record.productionReady===false
    &&record.previousBudgetWei===String(CAP)&&record.budgetWei===String(ASP_BUDGET_EXTENSION_CAP_WEI)&&record.authorization==='explicit-user-approval','TESTNET_BUDGET_EXTENSION_NOT_APPROVED');
  return record;
}

/** Trusted local callback injection; this module never signs or sends a tx. */
export async function createASPBudgetGuard({client,profile,directory,rootDirectory=process.cwd(),budgetWei=CAP,minimumCombinedFeeWei=0n,budgetExtension=null}){
  const policy=createASPBudgetPolicy({profile,budgetWei,minimumCombinedFeeWei,budgetExtension});
  const root=path.resolve(rootDirectory),dir=path.resolve(directory);
  check(dir.startsWith(root+path.sep),'BUDGET_DIRECTORY_OUTSIDE_WORKSPACE');
  if(policy.budgetExtension)await readASPBudgetExtensionAuthorization({rootDirectory:root,budgetExtension:policy.budgetExtension});
  await fs.mkdir(dir,{recursive:true,mode:0o700});const stat=await fs.lstat(dir);
  check(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0&&await fs.realpath(dir)===dir,'UNSAFE_BUDGET_DIRECTORY');
  const identity=policy.identity;
  const filename=path.join(dir,'shared-fees.json'),relative=path.relative(root,filename),policyFile=path.join(dir,'budget-policy.json');
  async function assertPolicy({initialize=false}={}){
    if(policy.budgetExtension){
      await readASPBudgetExtensionAuthorization({rootDirectory:root,budgetExtension:policy.budgetExtension});
      const previous=await readPinnedExtensionFile(path.join(dir,`budget-policy.before-${policy.budgetExtension.previousPolicySHA256}.json`),policy.budgetExtension.previousPolicySHA256);
      const expected=createASPBudgetPolicy({profile,budgetWei:CAP,minimumCombinedFeeWei});
      check(JSON.stringify(previous)===JSON.stringify(expected),'TESTNET_BUDGET_EXTENSION_PREVIOUS_POLICY_MISMATCH');
    }
    const current=await read(policyFile,true);
    check(current?JSON.stringify(current)===JSON.stringify(policy):initialize&&!policy.budgetExtension,'TESTNET_BUDGET_POLICY_CHANGED');
    const combined=await readCombinedTestnetFees(root);
    check(combined>=minimumCombinedFeeWei,'TESTNET_BUDGET_HISTORY_BELOW_FLOOR');
    check(combined<=budgetWei,'AGGREGATE_TESTNET_GAS_BUDGET_EXCEEDED');
    if(!current)await atomic(policyFile,policy);
    return combined;
  }
  const archiveFile=path.join(root,'artifacts/phase1/archived-testnet-fees.json');
  const spendingLock=path.join(root,'artifacts/phase1-service/testnet/spending/.spending.lock');
  let tail=Promise.resolve();
  async function exclusive(fn){const p=tail.then(async()=>{const unlock=await lock(spendingLock);let unlockArchive;try{unlockArchive=await lock(path.join(path.dirname(archiveFile),'.archived-testnet-fees.lock'));return await fn();}finally{await unlockArchive?.();await unlock();}});tail=p.catch(()=>{});return p;}
  const load=async()=>validateJournal(await read(filename,true)??{schema:'phase2-asp-shared-fees/v1',identity,chainId:46630,genesisHash:GENESIS,jobs:[]},identity);
  async function save(journal){
    validateJournal(journal,identity);await assertPolicy();const archive=await read(archiveFile);
    check(archive?.schema==='phase1-archived-testnet-fees/v1'&&Array.isArray(archive.entries),'INVALID_SHARED_FEE_ARCHIVE');
    const seen=new Set();for(const e of archive.entries){check(typeof e.journal==='string'&&!seen.has(e.journal),'INVALID_FEE_ARCHIVE_ENTRY');seen.add(e.journal);integer(e.feeWei);}
    // All ASP pool runtimes participate in the same sender/nonce reservation
    // under this global lock, even when operators chose different state dirs.
    const ourNonces=new Set(journal.jobs.map(j=>`${j.processor}:${j.nonce}`));
    for(const e of archive.entries){
      if(e.journal===relative||!e.journal.endsWith('/shared-fees.json'))continue;
      const otherFile=path.resolve(root,e.journal);check(otherFile.startsWith(root+path.sep),'UNSAFE_SHARED_FEE_REFERENCE');
      const other=await read(otherFile);validateJournal(other,other.identity);
      check(!other.jobs.some(j=>ourNonces.has(`${j.processor}:${j.nonce}`)),'CROSS_JOURNAL_BUDGET_NONCE_CONFLICT');
    }
    const old=archive.entries.find(e=>e.journal===relative),own=old?integer(old.feeWei):0n,total=await readCombinedTestnetFees(root),next=cost(journal);
    check(total>=own&&total-own+next<=budgetWei,'AGGREGATE_TESTNET_GAS_BUDGET_EXCEEDED');
    // The reservation is durable before authorizeFee returns. An orphaned
    // unsigned entry conservatively continues reserving its ceiling.
    await atomic(filename,journal);
    const entry={journal:relative,artifactSHA256:profile.artifactSHA256,feeWei:String(next),accounting:'confirmed-actual-plus-unresolved-ceilings',testOnly:true};
    if(old)archive.entries[archive.entries.indexOf(old)]=entry;else archive.entries.push(entry);
    await atomic(archiveFile,archive);
    check(await readCombinedTestnetFees(root)<=budgetWei,'GLOBAL_RESERVATION_READBACK_FAILED');
  }
  const assertChain=async()=>check(await client.getChainId()===46630&&(await client.getBlock({blockNumber:0n})).hash===GENESIS,'TESTNET_BUDGET_CHAIN_CHANGED');
  await assertChain();await exclusive(async()=>{await assertPolicy({initialize:true});const j=await load();if(j.jobs.length)await save(j);});
  return {
    async authorizeFee(input){await assertChain();return exclusive(async()=>{
      const x=wire(input);check(x.chainId===46630&&typeof x.jobId==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(x.jobId)&&/^0x[0-9a-f]{40}$/i.test(x.processor)&&Number.isSafeInteger(x.nonce)&&x.nonce>=0,'INVALID_BUDGET_INTENT');
      check(integer(x.gas)>0n&&integer(x.gasPrice)>0n&&integer(x.feeCeilingWei)===integer(x.gas)*integer(x.gasPrice),'INVALID_BUDGET_FEE_CEILING');
      check(/^0x[0-9a-f]{40}$/i.test(x.to)&&/^0x(?:[0-9a-f]{2})*$/i.test(x.data),'INVALID_BUDGET_CALL');
      const fingerprint=sha({processor:x.processor.toLowerCase(),nonce:x.nonce,chainId:x.chainId,to:x.to.toLowerCase(),data:x.data.toLowerCase(),gas:x.gas,gasPrice:x.gasPrice,ceiling:x.feeCeilingWei,value:x.value??'0'}),j=await load(),old=j.jobs.find(v=>v.id===x.jobId);
      if(old)check(old.fingerprint===fingerprint,'BUDGET_IDEMPOTENCY_CONFLICT');
      else j.jobs.push({id:x.jobId,fingerprint,processor:x.processor.toLowerCase(),nonce:x.nonce,to:x.to.toLowerCase(),data:x.data.toLowerCase(),gas:x.gas,gasPrice:x.gasPrice,value:x.value??'0',ceiling:x.feeCeilingWei,status:'reserved'});
      await save(j);return {reservedWei:String(cost(j)),budgetWei:String(budgetWei)};
    });},
    async settleFee({job,receipt}){await assertChain();return exclusive(async()=>{
      const j=await load(),entry=j.jobs.find(v=>v.id===job.id);check(entry,'UNRESERVED_RELAY_RECEIPT');
      check(hash(receipt.transactionHash)&&receipt.transactionHash===job.hash&&hash(receipt.blockHash)&&receipt.from?.toLowerCase()===entry.processor&&['success','reverted'].includes(receipt.status),'INVALID_BUDGET_RECEIPT');
      check(typeof receipt.gasUsed==='bigint'&&typeof receipt.effectiveGasPrice==='bigint'&&receipt.gasUsed>=0n&&receipt.effectiveGasPrice>0n,'INVALID_BUDGET_RECEIPT_FEE');
      // Robinhood's L2 may charge less than the signed legacy gas-price bid.
      // Treat the bid as a ceiling only for the paid receipt: the independent
      // canonical receipt and exact on-chain transaction bid still match below.
      check(receipt.to?.toLowerCase()===entry.to&&receipt.gasUsed<=integer(entry.gas)&&receipt.effectiveGasPrice<=integer(entry.gasPrice),'BUDGET_RECEIPT_FEE_OR_TARGET_MISMATCH');
      const canonical=await client.getTransactionReceipt({hash:job.hash});
      check(canonical.transactionHash===receipt.transactionHash&&canonical.blockHash===receipt.blockHash&&canonical.blockNumber===receipt.blockNumber
        &&canonical.status===receipt.status&&canonical.gasUsed===receipt.gasUsed&&canonical.effectiveGasPrice===receipt.effectiveGasPrice
        &&canonical.from?.toLowerCase()===entry.processor&&canonical.to?.toLowerCase()===entry.to,'BUDGET_NONCANONICAL_RECEIPT');
      const tx=await client.getTransaction({hash:job.hash});
      check(tx.hash===job.hash&&tx.chainId===46630&&tx.nonce===entry.nonce&&tx.from?.toLowerCase()===entry.processor&&tx.to?.toLowerCase()===entry.to
        &&(tx.input??tx.data).toLowerCase()===entry.data&&(tx.value??0n)===integer(entry.value)&&tx.gas===integer(entry.gas)
        &&(tx.gasPrice??tx.maxFeePerGas)===integer(entry.gasPrice),'BUDGET_RECEIPT_INTENT_MISMATCH');
      check((await client.getBlock({blockNumber:receipt.blockNumber})).hash===receipt.blockHash,'BUDGET_RECEIPT_REORGANIZED');
      const fee=receipt.gasUsed*receipt.effectiveGasPrice;check(fee<=integer(entry.ceiling),'BUDGET_RECEIPT_EXCEEDS_CEILING');
      if(entry.status==='settled')check(entry.hash===receipt.transactionHash&&entry.blockHash===receipt.blockHash&&entry.fee===String(fee),'BUDGET_SETTLEMENT_CHANGED');
      Object.assign(entry,{status:'settled',hash:receipt.transactionHash,blockHash:receipt.blockHash,fee:String(fee)});await save(j);
    });},
    async snapshot(){return exclusive(async()=>{await assertPolicy();return {schema:'phase2-asp-shared-budget/v1',budgetWei:String(budgetWei),combinedFeeWei:String(await readCombinedTestnetFees(root)),reservedOrSpentWei:String(cost(await load())),minimumCombinedFeeWei:String(minimumCombinedFeeWei)};});},
  };
}
