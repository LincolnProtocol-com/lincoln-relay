// Offline binding of a completed public-beacon workflow to both real zkey chains.
// Mathematical verification remains mandatory in the finalizer/mainnet builder.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual as same} from 'node:util';
import {immutablePublicationURL,validateBeaconRPCs} from './beacon.mjs';
import {verifyCeremonyFreeze} from './prepare.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const DEFAULT='artifacts/phase2-ceremony/beacon-commitment.applied.json';
const FREEZE_SHA='72922c85f0877f9eb45f1ac7b15f16a9ecb92194fded598079c3435740798398';
const GENESIS='0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const NAMES=['joinsplit','holder-exit'];
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const sorted=value=>value&&typeof value==='object'?(Array.isArray(value)?value.map(sorted):Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])]))):value;
export const beaconEvidenceDigest=value=>sha(JSON.stringify(sorted(value)));
function safe(relative){check(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(p=>p&&!p.startsWith('.')&&p!=='..'),'BEACON_EVIDENCE_PUBLIC_PATH_REQUIRED');return relative;}
async function file(root,relative){
  const absolute=path.join(root,safe(relative)),stat=await fs.lstat(absolute);
  check(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(absolute)===absolute,'BEACON_EVIDENCE_REGULAR_FILE_REQUIRED');
  check(stat.size>0&&stat.size<=(relative.endsWith('.json')?2*1024*1024:128*1024*1024),'BEACON_EVIDENCE_FILE_TOO_LARGE');
  const bytes=await fs.readFile(absolute);return {path:relative,absolute,bytes,sha256:sha(bytes)};
}
const reference=f=>({path:f.path,sha256:f.sha256,bytes:f.bytes.length});
async function bound(root,ref){
  check(ref&&/^[a-f0-9]{64}$/.test(ref.sha256)&&Number.isSafeInteger(ref.bytes)&&ref.bytes>0,'BEACON_EVIDENCE_REFERENCE_INVALID');
  const actual=await file(root,ref.path);check(same(reference(actual),ref),'BEACON_EVIDENCE_FILE_DIGEST_MISMATCH');return actual;
}
const parse=f=>{try{return JSON.parse(f.bytes);}catch{check(false,'BEACON_EVIDENCE_JSON_INVALID');}};
function number(value){check(typeof value==='string'&&/^0x(?:0|[1-9a-f][a-f0-9]*)$/.test(value),'BEACON_EVIDENCE_QUANTITY_INVALID');return BigInt(value);}
function hash(value){check(typeof value==='string'&&/^0x[a-f0-9]{64}$/.test(value),'BEACON_EVIDENCE_HASH_INVALID');return value;}
function header(h){
  check(h&&typeof h==='object','BEACON_EVIDENCE_HEADER_INVALID');number(h.number);number(h.timestamp);
  for(const name of ['hash','parentHash','stateRoot','receiptsRoot','transactionsRoot'])hash(h[name]);return h;
}
function source(s,target,hosts){
  check(s&&s.chainId===1&&s.genesisHash===GENESIS&&number(s.blockNumber)===target&&Array.isArray(s.rpcHosts)&&s.rpcHosts.length===2,'BEACON_EVIDENCE_SOURCE_INVALID');
  check(same(validateBeaconRPCs(s.rpcHosts.map(h=>'https://'+h)),s.rpcHosts)&&(!hosts||same(s.rpcHosts,hosts)),'BEACON_EVIDENCE_RPC_HOSTS_INVALID');
  check(Array.isArray(s.observedTips)&&s.observedTips.length===2&&s.observedTips.every(tip=>number(header(tip).number)+128n<=target),'BEACON_EVIDENCE_TARGET_WAS_NOT_FUTURE');
  header(s.commonHeader);check(s.observedTips.every(tip=>number(tip.number)>=number(s.commonHeader.number)&&number(tip.timestamp)>=number(s.commonHeader.timestamp)),'BEACON_EVIDENCE_COMMON_HEADER_INVALID');
  check(s.independentRPCOperatorsAuthenticated===false&&s.localTimeProvesPublicCommitment===false,'BEACON_EVIDENCE_UNSUPPORTED_AUTHENTICATION_CLAIM');
  return s;
}
async function actualChain(root,zkeyPath){const {inspectContributionChain}=await import('./contribute.mjs');return inspectContributionChain({rootDirectory:root,zkeyPath});}
async function approvedFreeze(root){
  const freeze=parse(await file(root,'artifacts/phase2-ceremony/asp-preparation-20261015-r4/freeze.json'));
  check(freeze.freezeSHA256===FREEZE_SHA,'BEACON_EVIDENCE_APPROVED_FREEZE_CHANGED');
  await verifyCeremonyFreeze(freeze,{rootDirectory:root});
}
export function createBeaconEvidenceLoader({inspect=actualChain,verify=approvedFreeze}={}){
  return async function load({rootDirectory=ROOT,applicationPath=DEFAULT}={}){
    const root=await fs.realpath(rootDirectory);safe(applicationPath);
    check(/^artifacts\/phase2-ceremony\/[A-Za-z0-9_/-]+\.applied\.json$/.test(applicationPath),'BEACON_EVIDENCE_APPLICATION_PATH_INVALID');
    const applicationFile=await file(root,applicationPath),application=parse(applicationFile),refs=application.beaconEvidence;
    await verify(root);
    check(application.schema==='phase2-future-beacon-plan/v1'&&application.mode==='apply'&&application.executed===true
      &&application.transactionsBroadcast===0&&application.finalParametersCreated===true&&application.cryptographicVerificationExecuted===true
      &&application.productionReady===false&&application.independentOperatorIdentityAuthenticated===false
      &&refs?.schema==='phase2-beacon-evidence/v1'&&refs.publicPrecommitTimingCryptographicallyAuthenticated===false,'BEACON_EVIDENCE_APPLICATION_INVALID');
    const base=applicationPath.replace(/\.applied\.json$/,'');
    check(refs.commitment?.path===base+'.json'&&refs.publication?.path===base+'.publication.json'&&refs.observation?.path===base+'.observation.json','BEACON_EVIDENCE_PATH_BINDING_INVALID');
    const commitmentFile=await bound(root,refs.commitment),publicationFile=await bound(root,refs.publication),observationFile=await bound(root,refs.observation);
    const commitment=parse(commitmentFile),publication=parse(publicationFile),observation=parse(observationFile);
    check(commitment.schema==='phase2-future-beacon-commitment/v1'&&commitment.sha256===beaconEvidenceDigest(commitment.body)
      &&commitment.body.schema==='phase2-future-beacon-inputs/v1'&&commitment.body.freezeSHA256===FREEZE_SHA
      &&application.commitmentSHA256===commitment.sha256&&application.commitmentPath===commitmentFile.path,'BEACON_EVIDENCE_COMMITMENT_INVALID');
    const iterations=commitment.body.iterations;check(Number.isInteger(iterations)&&iterations>=10&&iterations<=24,'BEACON_EVIDENCE_ITERATIONS_OUT_OF_BOUNDS');
    const target=number(commitment.body.source.blockNumber),committedSource=source(commitment.body.source,target);
    check(publication.schema==='phase2-beacon-publication-observation/v1'&&publication.sha256===beaconEvidenceDigest(publication.body)
      &&publication.body.commitmentSHA256===commitment.sha256&&publication.body.commitmentFileSHA256===commitmentFile.sha256
      &&publication.body.publicPrecommitTimingCryptographicallyAuthenticated===false,'BEACON_EVIDENCE_PUBLICATION_INVALID');
    immutablePublicationURL(publication.body.url);source(publication.body.source,target,committedSource.rpcHosts);
    check(observation.schema==='phase2-future-beacon-observation/v1'&&observation.chainId===1&&observation.genesisHash===GENESIS
      &&observation.commitmentSHA256===commitment.sha256&&observation.publicationObservationSHA256===publication.sha256
      &&same(observation.rpcHosts,committedSource.rpcHosts)&&observation.independentRPCOperatorsAuthenticated===false
      &&observation.publicPrecommitTimingCryptographicallyAuthenticated===false,'BEACON_EVIDENCE_OBSERVATION_INVALID');
    const beaconHash=hash(observation.beaconHash);check(header(observation.beaconHeader).hash===beaconHash
      &&number(observation.beaconHeader.number)===target&&application.beaconHash===beaconHash&&application.evidencePath===observationFile.path,'BEACON_EVIDENCE_BEACON_MISMATCH');
    check(Array.isArray(observation.finalizedHeaders)&&observation.finalizedHeaders.length===2
      &&observation.finalizedHeaders.every(h=>number(header(h).number)>=target),'BEACON_EVIDENCE_TARGET_NOT_FINALIZED');
    const circuits={};let names;
    for(const name of NAMES){
      const parent=commitment.body.circuits?.[name],applied=application.circuits?.[name];
      check(parent?.circuit===name&&applied&&applied.file?.path===`protocol/phase2-mainnet/build/${name}/final.zkey`,'BEACON_EVIDENCE_CIRCUIT_BINDING_INVALID');
      safe(parent.zkey?.path);
      check((parent.zkey.path.startsWith(`protocol/phase2-mainnet/build/${name}/`)&&parent.zkey.path.endsWith('.zkey')&&!parent.zkey.path.endsWith('/final.zkey'))
        ||new RegExp(`^artifacts/phase2-ceremony/contributions/[a-z][a-z0-9-]{2,63}/${name}\\.zkey$`).test(parent.zkey.path),'BEACON_EVIDENCE_PARENT_PATH_INVALID');
      const baseline=parse(await file(root,`artifacts/phase2-asp/circuits/${name}/manifest.json`));
      check(parent.r1cs?.path===`protocol/phase2-mainnet/build/${name}/main.r1cs`&&parent.wasm?.path===`protocol/phase2-mainnet/build/${name}/main_js/main.wasm`
        &&parent.ptau?.path===baseline.phase1.path&&parent.ptau.sha256===baseline.phase1.sha256&&same(parent.sources,baseline.inputs.sources),'BEACON_EVIDENCE_COMPUTATION_BINDING_INVALID');
      for(const item of ['r1cs','wasm','ptau'])await bound(root,parent[item]);
      check(parent.r1cs.sha256===baseline.artifacts.r1cs.sha256&&parent.wasm.sha256===baseline.artifacts.wasm.sha256,'BEACON_EVIDENCE_APPROVED_COMPUTATION_MISMATCH');
      for(const input of parent.sources)check((await file(root,input.path)).sha256===input.sha256,'BEACON_EVIDENCE_SOURCE_CHANGED');
      const inputFile=await bound(root,parent.zkey),finalFile=await bound(root,applied.file);
      check(finalFile.sha256!==baseline.artifacts.zkey.sha256&&finalFile.sha256!==inputFile.sha256,'BEACON_EVIDENCE_DEVELOPMENT_KEY_REUSE');
      const previous=await inspect(root,inputFile.absolute),current=await inspect(root,finalFile.absolute);
      check(previous.length>=2&&previous.length<=10000&&previous.every(c=>c.type===0&&typeof c.name==='string'&&c.name.length>0
        &&/^0x[a-f0-9]{128}$/.test(c.contributionHashHex??'')&&/^0x[a-f0-9]{128}$/.test(c.transcriptHex??''))
        &&new Set(previous.map(c=>c.name)).size===previous.length,'BEACON_EVIDENCE_CONTRIBUTORS_INVALID');
      check(same(parent.contributions,previous)&&current.length===previous.length+1&&same(current.slice(0,-1),previous)
        &&same(current,applied.contributions),'BEACON_EVIDENCE_FULL_PREFIX_MISMATCH');
      const tail=current.at(-1);check(tail.type===1&&tail.beaconHash===beaconHash&&tail.numIterationsExp===iterations
        &&/^0x[a-f0-9]{128}$/.test(tail.contributionHashHex??''),'BEACON_EVIDENCE_FINAL_BEACON_RECORD_MISMATCH');
      const operators=previous.map(c=>c.name);check(!names||same(names,operators),'BEACON_EVIDENCE_CIRCUIT_OPERATORS_DIFFER');names=operators;
      circuits[name]={parentZkey:reference(inputFile),finalZkey:reference(finalFile),contributions:current,nonBeaconContributors:previous.length};
    }
    return {schema:'phase2-verified-beacon-application/v1',application:reference(applicationFile),commitment:reference(commitmentFile),
      publication:reference(publicationFile),observation:reference(observationFile),beaconHash,iterations,circuits,
      independentOperatorIdentityAuthenticated:false,publicPrecommitTimingCryptographicallyAuthenticated:false,
      cryptographicVerificationExecuted:false,networkRequests:0};
  };
}
export const loadVerifiedBeaconApplication=createBeaconEvidenceLoader();
