#!/usr/bin/env node
// Fix both input keys before selecting future public Ethereum randomness.
// This tool never signs or broadcasts. Public publication is observed, not timestamp-authenticated.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {verifyCeremonyFreeze} from './prepare.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const CIRCUITS=['joinsplit','holder-exit'];
const PTAU='vendor/nocturne-protocol/packages/circuits/data/powersOfTau28_hez_final_15.ptau';
const GENESIS='0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const DEFAULT_COMMITMENT='artifacts/phase2-ceremony/beacon-commitment.json';
const MIN_FUTURE_BLOCKS=128n;
const FREEZE='artifacts/phase2-ceremony/asp-preparation-20261015-r4/freeze.json';
const FREEZE_SHA='72922c85f0877f9eb45f1ac7b15f16a9ecb92194fded598079c3435740798398';
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const wire=value=>JSON.stringify(value,null,2)+'\n';
const canonical=value=>JSON.stringify(value&&typeof value==='object'?(Array.isArray(value)?value.map(v=>JSON.parse(canonical(v))):Object.fromEntries(Object.keys(value).sort().map(k=>[k,JSON.parse(canonical(value[k]))]))):value);
const digest=value=>sha(canonical(value));
const hex=value=>'0x'+BigInt(value).toString(16);
function quantity(value){check(typeof value==='string'&&/^0x(?:0|[1-9a-f][a-f0-9]*)$/.test(value),'BEACON_RPC_QUANTITY_INVALID');return BigInt(value);}
function hash(value){check(typeof value==='string'&&/^0x[a-f0-9]{64}$/.test(value),'BEACON_HASH_INVALID');return value;}
function publicPath(relative){
  check(typeof relative==='string'&&!path.isAbsolute(relative)&&!relative.includes('\\')&&relative.split('/').every(p=>p&&!p.startsWith('.')&&p!=='..'),'BEACON_PUBLIC_PATH_REQUIRED');
  return relative;
}
async function file(root,relative){
  const filename=path.join(root,publicPath(relative)),st=await fs.lstat(filename);
  check(st.isFile()&&!st.isSymbolicLink()&&await fs.realpath(filename)===filename,'BEACON_REGULAR_FILE_REQUIRED');
  const bytes=await fs.readFile(filename);return {path:relative,filename,bytes,sha256:sha(bytes)};
}
async function fresh(root,relative,bytes){
  const filename=path.join(root,publicPath(relative)),parent=path.dirname(filename);await fs.mkdir(parent,{recursive:true});
  check(await fs.realpath(parent)===parent,'BEACON_OUTPUT_DIRECTORY_INVALID');
  const handle=await fs.open(filename,'wx',0o644);try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
}
function reference(f){return {path:f.path,sha256:f.sha256,bytes:f.bytes.length};}
function header(block){
  check(block&&typeof block==='object','BEACON_BLOCK_UNAVAILABLE');
  return {number:hex(quantity(block.number)),hash:hash(block.hash),parentHash:hash(block.parentHash),timestamp:hex(quantity(block.timestamp)),
    stateRoot:hash(block.stateRoot),receiptsRoot:hash(block.receiptsRoot),transactionsRoot:hash(block.transactionsRoot)};
}
export function validateBeaconRPCs(urls){
  check(Array.isArray(urls)&&urls.length===2,'BEACON_TWO_RPCS_REQUIRED');
  const parsed=urls.map(value=>{let u;try{u=new URL(value);}catch{check(false,'BEACON_RPC_URL_INVALID');}
    check(u.protocol==='https:'&&!u.username&&!u.password&&!u.hash,'BEACON_HTTPS_RPC_REQUIRED');return u;});
  check(parsed[0].hostname.toLowerCase()!==parsed[1].hostname.toLowerCase(),'BEACON_DISTINCT_RPC_HOSTS_REQUIRED');
  return parsed.map(u=>u.hostname.toLowerCase());
}
async function rpc(url,method,params=[]){
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(15000)});
  check(response.ok,'BEACON_RPC_HTTP_FAILED');const text=await response.text();check(text.length<=2000000,'BEACON_RPC_RESPONSE_TOO_LARGE');
  let body;try{body=JSON.parse(text);}catch{check(false,'BEACON_RPC_JSON_INVALID');}
  check(body.id===1&&body.jsonrpc==='2.0'&&!body.error&&Object.hasOwn(body,'result'),'BEACON_RPC_FAILED');return body.result;
}
async function paired(urls,request,method,params){return Promise.all(urls.map(url=>request(url,method,params)));}
async function verifyFrozen(root){
  const freeze=JSON.parse((await file(root,FREEZE)).bytes);check(freeze.freezeSHA256===FREEZE_SHA,'BEACON_APPROVED_FREEZE_CHANGED');
  await verifyCeremonyFreeze(freeze,{rootDirectory:root});
}
async function frozenSnark(root){return import(pathToFileURL(path.join(root,'scripts/private-transfer/deps/node_modules/snarkjs/main.js')).href);}
async function identity(urls,request){
  validateBeaconRPCs(urls);
  check((await paired(urls,request,'eth_chainId',[])).every(n=>quantity(n)===1n),'BEACON_ETHEREUM_MAINNET_REQUIRED');
  const genesis=(await paired(urls,request,'eth_getBlockByNumber',['0x0',false])).map(header);
  check(genesis.every(b=>b.number==='0x0'&&b.hash===GENESIS)&&isDeepStrictEqual(genesis[0],genesis[1]),'BEACON_GENESIS_MISMATCH');
  return genesis[0];
}
export async function observeFutureBeacon({rpcUrls,blockNumber,request=rpc}={}){
  const target=quantity(blockNumber),hosts=validateBeaconRPCs(rpcUrls),genesis=await identity(rpcUrls,request);
  const tips=(await paired(rpcUrls,request,'eth_getBlockByNumber',['latest',false])).map(header);
  const max=tips.reduce((n,b)=>quantity(b.number)>n?quantity(b.number):n,0n),min=tips.reduce((n,b)=>quantity(b.number)<n?quantity(b.number):n,max);
  check(max-min<=8n,'BEACON_RPC_HEADS_DIVERGED');check(target>=max+MIN_FUTURE_BLOCKS,'BEACON_TARGET_NOT_FUTURE_ENOUGH');
  const common=(await paired(rpcUrls,request,'eth_getBlockByNumber',[hex(min),false])).map(header);
  check(isDeepStrictEqual(common[0],common[1])&&common[0].number===hex(min),'BEACON_RPC_HEADERS_DISAGREE');
  check(common.every(b=>quantity(b.timestamp)<=quantity(tips[common.indexOf(b)].timestamp)),'BEACON_RPC_TIMESTAMP_INVALID');
  return {chainId:1,genesisHash:genesis.hash,rpcHosts:hosts,observedTips:tips,commonHeader:common[0],blockNumber:hex(target),
    minimumFutureBlocks:Number(MIN_FUTURE_BLOCKS),independentRPCOperatorsAuthenticated:false,localTimeProvesPublicCommitment:false};
}
export function immutablePublicationURL(value){
  let url;try{url=new URL(value);}catch{check(false,'BEACON_PUBLICATION_URL_INVALID');}
  check(url.protocol==='https:'&&url.hostname==='raw.githubusercontent.com'&&!url.username&&!url.password&&!url.port&&!url.search&&!url.hash
    &&/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/[a-f0-9]{40}\/[A-Za-z0-9_./-]+$/.test(url.pathname)
    &&!url.pathname.split('/').includes('..'),'BEACON_IMMUTABLE_GITHUB_URL_REQUIRED');
  return url.href;
}
async function fetchPublication(url){
  const response=await fetch(immutablePublicationURL(url),{signal:AbortSignal.timeout(15000),redirect:'error'});
  check(response.ok,'BEACON_PUBLICATION_FETCH_FAILED');
  check(Number(response.headers.get('content-length')??0)<=2000000,'BEACON_PUBLICATION_TOO_LARGE');
  const data=new Uint8Array(await response.arrayBuffer());check(data.length<=2000000,'BEACON_PUBLICATION_TOO_LARGE');return Buffer.from(data);
}
function validCommitment(commitment){
  check(commitment?.schema==='phase2-future-beacon-commitment/v1'&&commitment.sha256===digest(commitment.body),'BEACON_COMMITMENT_DIGEST_MISMATCH');
  check(commitment.body.schema==='phase2-future-beacon-inputs/v1'&&commitment.body.freezeSHA256===FREEZE_SHA,'BEACON_COMMITMENT_FREEZE_MISMATCH');
  check(commitment.body.source.chainId===1&&commitment.body.source.genesisHash===GENESIS,'BEACON_COMMITMENT_SOURCE_INVALID');
  check(Number.isInteger(commitment.body.iterations)&&commitment.body.iterations>=10&&commitment.body.iterations<=24,'BEACON_ITERATIONS_OUT_OF_BOUNDS');
  return quantity(commitment.body.source.blockNumber);
}
export async function observeFinalBeacon({rpcUrls,commitment,publication,request=rpc}={}){
  const target=validCommitment(commitment),hosts=validateBeaconRPCs(rpcUrls);await identity(rpcUrls,request);
  check(publication?.schema==='phase2-beacon-publication-observation/v1'&&publication.sha256===digest(publication.body)
    &&publication.body.commitmentSHA256===commitment.sha256,'BEACON_PUBLICATION_BINDING_INVALID');
  immutablePublicationURL(publication.body.url);
  const observed=publication.body.source;
  check(observed?.chainId===1&&observed.genesisHash===GENESIS&&observed.blockNumber===hex(target)
    &&isDeepStrictEqual(observed.rpcHosts,hosts)&&Array.isArray(observed.observedTips)&&observed.observedTips.length===2
    &&observed.observedTips.every(tip=>quantity(tip.number)+MIN_FUTURE_BLOCKS<=target),'BEACON_PUBLICATION_FUTURE_OBSERVATION_INVALID');
  const finalized=(await paired(rpcUrls,request,'eth_getBlockByNumber',['finalized',false])).map(header);
  check(finalized.every(b=>quantity(b.number)>=target),'BEACON_TARGET_NOT_FINALIZED');
  const beacons=(await paired(rpcUrls,request,'eth_getBlockByNumber',[hex(target),false])).map(header);
  check(isDeepStrictEqual(beacons[0],beacons[1])&&beacons[0].number===hex(target),'BEACON_RPC_HEADERS_DISAGREE');
  return {schema:'phase2-future-beacon-observation/v1',chainId:1,genesisHash:GENESIS,rpcHosts:hosts,finalizedHeaders:finalized,
    beaconHeader:beacons[0],beaconHash:beacons[0].hash,publicationObservationSHA256:publication.sha256,
    commitmentSHA256:commitment.sha256,independentRPCOperatorsAuthenticated:false,publicPrecommitTimingCryptographicallyAuthenticated:false,
    trust:'Publication was observed via immutable GitHub bytes while two distinct HTTPS RPC hosts reported a future target. The local observation is not a cryptographic timestamp; Ethereum finality is RPC-reported, not verified by a consensus light client.'};
}
async function readCircuit(root,name,relative){
  check(CIRCUITS.includes(name),'BEACON_CIRCUIT_INVALID');
  publicPath(relative);
  check((relative.startsWith('protocol/phase2-mainnet/build/'+name+'/')&&relative.endsWith('.zkey')&&!relative.endsWith('/final.zkey'))
    ||new RegExp(`^artifacts/phase2-ceremony/contributions/[a-z][a-z0-9-]{2,63}/${name}\\.zkey$`).test(relative),'BEACON_INPUT_KEY_PATH_INVALID');
  const {inspectContributionChain}=await import('./contribute.mjs');
  const base=`protocol/phase2-mainnet/build/${name}`,input=await file(root,relative),r1cs=await file(root,`${base}/main.r1cs`),wasm=await file(root,`${base}/main_js/main.wasm`);
  const baseline=JSON.parse((await file(root,`artifacts/phase2-asp/circuits/${name}/manifest.json`)).bytes);
  check(r1cs.sha256===baseline.artifacts.r1cs.sha256&&wasm.sha256===baseline.artifacts.wasm.sha256,'BEACON_COMPUTATION_MISMATCH');
  const ptau=await file(root,PTAU);check(ptau.sha256===baseline.phase1.sha256,'BEACON_PHASE1_MISMATCH');
  for(const source of baseline.inputs.sources)check((await file(root,source.path)).sha256===source.sha256,'BEACON_SOURCE_CHANGED');
  const contributions=await inspectContributionChain({rootDirectory:root,zkeyPath:input.filename});
  check(contributions.length>=2&&contributions.length<=10000&&contributions.every(c=>c.type===0&&typeof c.name==='string'&&c.name.length>0)
    &&new Set(contributions.map(c=>c.name)).size===contributions.length,'BEACON_TWO_NONBEACON_CONTRIBUTIONS_REQUIRED');
  const {zKey}=await frozenSnark(root);
  try{check(await zKey.verifyFromR1cs(r1cs.filename,ptau.bytes,input.filename,{debug(){},info(){},warn(){},error(){}})===true,'BEACON_INPUT_KEY_VERIFICATION_FAILED');}
  finally{if(globalThis.curve_bn128){await globalThis.curve_bn128.terminate();globalThis.curve_bn128=undefined;}}
  return {circuit:name,zkey:reference(input),r1cs:reference(r1cs),wasm:reference(wasm),ptau:reference(ptau),sources:baseline.inputs.sources,contributions};
}
async function applyKey(root,name,inputPath,outputPath,beaconHash,iterations){
  const {zKey}=await frozenSnark(root),quiet={debug(){},info(){},warn(){},error(){}};
  try{check(await zKey.beacon(path.join(root,inputPath),path.join(root,outputPath),'Ethereum future block final beacon',beaconHash.slice(2),iterations,quiet),'BEACON_APPLICATION_FAILED');
    check(await zKey.verifyFromR1cs(path.join(root,`protocol/phase2-mainnet/build/${name}/main.r1cs`),(await file(root,PTAU)).bytes,path.join(root,outputPath),quiet)===true,'BEACON_FINAL_KEY_VERIFICATION_FAILED');}
  finally{if(globalThis.curve_bn128){await globalThis.curve_bn128.terminate();globalThis.curve_bn128=undefined;}}
  const {inspectContributionChain}=await import('./contribute.mjs');
  return {file:reference(await file(root,outputPath)),contributions:await inspectContributionChain({rootDirectory:root,zkeyPath:path.join(root,outputPath)})};
}
// Injected dependencies support bounded offline tests; the CLI uses only the real defaults.
export function createBeaconOperations({request=rpc,inspect=readCircuit,apply=applyKey,readPublication=fetchPublication,verify=verifyFrozen}={}){
  return async function beaconCeremony({mode='plan',rootDirectory=ROOT,inputPaths,rpcUrls,blockNumber,iterations=20,commitmentPath=DEFAULT_COMMITMENT,publicationURL}={}){
    const plan={schema:'phase2-future-beacon-plan/v1',mode,executed:false,transactionsBroadcast:0,productionReady:false,
      minimumNonBeaconContributions:2,minimumFutureBlocks:Number(MIN_FUTURE_BLOCKS),requiresPublicPrecommit:true,
      publicPrecommit:'Publish the exact commitment bytes in an immutable GitHub commit, then run publish while the selected block remains at least 128 blocks in the future.',
      limitations:['Different RPC hostnames do not authenticate independent provider operators.','A local timestamp or Git commit does not prove timely public publication.','Contribution names do not authenticate independent people or secret destruction.']};
    check(['plan','commit','publish','apply'].includes(mode),'BEACON_MODE_INVALID');if(mode==='plan')return plan;
    const root=await fs.realpath(rootDirectory);publicPath(commitmentPath);check(commitmentPath.startsWith('artifacts/phase2-ceremony/')&&commitmentPath.endsWith('.json'),'BEACON_COMMITMENT_PATH_INVALID');
    check(Number.isInteger(iterations)&&iterations>=10&&iterations<=24,'BEACON_ITERATIONS_OUT_OF_BOUNDS');
    const lockPath=path.join(root,'protocol/phase2-mainnet/.beacon.lock'),lock=await fs.open(lockPath,'wx',0o600);
    try{
      await verify(root);
      if(mode==='commit'){
        check(inputPaths&&CIRCUITS.every(name=>typeof inputPaths[name]==='string'),'BEACON_BOTH_INPUT_KEYS_REQUIRED');
        const circuits={};for(const name of CIRCUITS)circuits[name]=await inspect(root,name,inputPaths[name]);
        const source=await observeFutureBeacon({rpcUrls,blockNumber,request});
        const body={schema:'phase2-future-beacon-inputs/v1',freezeSHA256:FREEZE_SHA,circuits,source,iterations};
        const commitment={schema:'phase2-future-beacon-commitment/v1',body,sha256:digest(body)};
        // Verify inputs again after network observation; never publish a mixed input snapshot.
        for(const name of CIRCUITS)check(isDeepStrictEqual(await inspect(root,name,inputPaths[name]),circuits[name]),'BEACON_INPUT_CHANGED');
        await verify(root);
        await fresh(root,commitmentPath,wire(commitment));
        return {...plan,executed:true,commitmentPath,commitmentSHA256:commitment.sha256,blockNumber:source.blockNumber,
          nextStep:'Commit and push this exact file to the public repository, then run --publish with its immutable raw.githubusercontent.com URL.',finalParametersCreated:false};
      }
      const commitmentFile=await file(root,commitmentPath),commitment=JSON.parse(commitmentFile.bytes);
      validCommitment(commitment);
      const publicationPath=commitmentPath.replace(/\.json$/,'.publication.json');
      if(mode==='publish'){
        const url=immutablePublicationURL(publicationURL),publicBytes=await readPublication(url);
        check(isDeepStrictEqual(publicBytes,commitmentFile.bytes),'BEACON_PUBLICATION_BYTES_MISMATCH');
        const source=await observeFutureBeacon({rpcUrls,blockNumber:commitment.body.source.blockNumber,request});
        check(isDeepStrictEqual(source.rpcHosts,commitment.body.source.rpcHosts),'BEACON_PUBLICATION_RPC_HOSTS_CHANGED');
        const body={commitmentSHA256:commitment.sha256,commitmentFileSHA256:commitmentFile.sha256,url,source,
          publicPrecommitTimingCryptographicallyAuthenticated:false,observedAtUTC:new Date().toISOString()};
        const publication={schema:'phase2-beacon-publication-observation/v1',body,sha256:digest(body)};
        await verify(root);
        await fresh(root,publicationPath,wire(publication));
        return {...plan,executed:true,publicationPath,publicationSHA256:publication.sha256,finalParametersCreated:false,
          publicPrecommitTimingCryptographicallyAuthenticated:false};
      }
      const publicationFile=await file(root,publicationPath),publication=JSON.parse(publicationFile.bytes);
      const observation=await observeFinalBeacon({rpcUrls,commitment,publication,request});
      check(publication.body.commitmentFileSHA256===commitmentFile.sha256
        &&isDeepStrictEqual(await readPublication(publication.body.url),commitmentFile.bytes),'BEACON_PUBLICATION_BYTES_MISMATCH');
      check(commitment.body.iterations>=10&&commitment.body.iterations<=24&&Number.isInteger(commitment.body.iterations),'BEACON_ITERATIONS_OUT_OF_BOUNDS');
      for(const name of CIRCUITS)check(isDeepStrictEqual(await inspect(root,name,commitment.body.circuits[name].zkey.path),commitment.body.circuits[name]),'BEACON_COMMITTED_INPUT_CHANGED');
      const evidencePath=commitmentPath.replace(/\.json$/,'.observation.json'),reportPath=commitmentPath.replace(/\.json$/,'.applied.json');
      const outputs=CIRCUITS.map(name=>`protocol/phase2-mainnet/build/${name}/final.zkey`);
      for(const p of [...outputs,evidencePath,reportPath]){try{await fs.lstat(path.join(root,p));check(false,'BEACON_OUTPUT_EXISTS');}catch(e){if(e.code!=='ENOENT')throw e;}}
      // Public source/header evidence is persisted before applying either circuit.
      await fresh(root,evidencePath,wire(observation));
      const staging=await fs.mkdtemp(path.join(root,'protocol/phase2-mainnet/build/beacon-staging-')),results={};
      try{
        for(const name of CIRCUITS){
          const relative=path.relative(root,path.join(staging,`${name}.zkey`));
          const result=await apply(root,name,commitment.body.circuits[name].zkey.path,relative,observation.beaconHash,commitment.body.iterations);
          const previous=commitment.body.circuits[name].contributions,tail=result.contributions.at(-1);
          check(result.contributions.length===previous.length+1&&isDeepStrictEqual(result.contributions.slice(0,-1),previous),'BEACON_CONTRIBUTION_PREFIX_CHANGED');
          check(tail.type===1&&tail.beaconHash===observation.beaconHash&&tail.numIterationsExp===commitment.body.iterations,'BEACON_FINAL_RECORD_MISMATCH');
          results[name]=result;
        }
        // Recheck the locked inputs once more before either final file is exposed.
        for(const name of CIRCUITS)check(isDeepStrictEqual(await inspect(root,name,commitment.body.circuits[name].zkey.path),commitment.body.circuits[name]),'BEACON_COMMITTED_INPUT_CHANGED');
        await verify(root);
        for(const [i,name]of CIRCUITS.entries()){
          const staged=await file(root,results[name].file.path);check(staged.sha256===results[name].file.sha256,'BEACON_OUTPUT_CHANGED');
          await fs.link(staged.filename,path.join(root,outputs[i]));results[name].file.path=outputs[i];
        }
        const report={...plan,executed:true,commitmentPath,commitmentSHA256:commitment.sha256,evidencePath,beaconHash:observation.beaconHash,
          beaconEvidence:{schema:'phase2-beacon-evidence/v1',commitment:reference(commitmentFile),publication:reference(publicationFile),
            observation:reference(await file(root,evidencePath)),publicPrecommitTimingCryptographicallyAuthenticated:false},
          circuits:results,finalParametersCreated:true,cryptographicVerificationExecuted:true,independentOperatorIdentityAuthenticated:false};
        await fresh(root,reportPath,wire(report));return report;
      }finally{await fs.rm(staging,{recursive:true,force:true});}
    }finally{await lock.close();await fs.unlink(lockPath);}
  };
}
export const prepareProductionBeacon=createBeaconOperations();
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const args=process.argv.slice(2),opts={mode:args.shift()?.replace(/^--/,'')??'plan'},values=new Map();
    while(args.length){const key=args.shift(),value=args.shift();check(key?.startsWith('--')&&value&&!value.startsWith('--')&&!values.has(key),'BEACON_USAGE');values.set(key,value);}
    check([...values.keys()].every(k=>['--joinsplit','--holder-exit','--rpc-a','--rpc-b','--block','--iterations','--commitment','--publication-url'].includes(k)),'BEACON_USAGE');
    opts.inputPaths={joinsplit:values.get('--joinsplit'),'holder-exit':values.get('--holder-exit')};opts.rpcUrls=[values.get('--rpc-a'),values.get('--rpc-b')];
    if(values.has('--block'))opts.blockNumber=values.get('--block');if(values.has('--iterations'))opts.iterations=Number(values.get('--iterations'));
    if(values.has('--commitment'))opts.commitmentPath=values.get('--commitment');if(values.has('--publication-url'))opts.publicationURL=values.get('--publication-url');
    console.log(JSON.stringify(await prepareProductionBeacon(opts),null,2));
  }catch(error){console.error(JSON.stringify({error:error.code??error.message,transactionsBroadcast:0,productionReady:false}));process.exitCode=1;}
}
