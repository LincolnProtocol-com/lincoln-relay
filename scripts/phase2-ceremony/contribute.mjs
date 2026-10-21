#!/usr/bin/env node
// One real operator, two frozen computations. Entropy exists only in a child process.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {verifyCeremonyFreeze} from './prepare.mjs';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const SELF=fileURLToPath(import.meta.url);
const FREEZE='artifacts/phase2-ceremony/asp-preparation-20261015-r4/freeze.json';
const DEPS='scripts/private-transfer/deps/node_modules';
const NAMES=['joinsplit','holder-exit'];
const sha=value=>createHash('sha256').update(value).digest('hex');
const wire=value=>JSON.stringify(value,null,2)+'\n';
const check=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
// snarkjs serializes names with substring(0,64); refuse silent truncation.
const validName=name=>typeof name==='string'&&/^[a-z][a-z0-9-]{2,63}$/.test(name);
const publicPath=value=>check(typeof value==='string'&&!path.isAbsolute(value)&&!value.includes('\\')&&
  value.split('/').every(part=>part&&!part.startsWith('.')&&part!=='..'),'CONTRIBUTION_PUBLIC_PATH_REQUIRED');
async function regular(root,relative){
  publicPath(relative);const absolute=path.join(root,relative),stat=await fs.lstat(absolute);
  check(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(absolute)===absolute,'CONTRIBUTION_REGULAR_FILE_REQUIRED');
  const bytes=await fs.readFile(absolute);return {path:relative,absolute,bytes};
}
const describe=file=>({path:file.path,bytes:file.bytes.length,sha256:sha(file.bytes)});
async function freshJSON(filename,value){
  const h=await fs.open(filename,'wx',0o644);try{await h.writeFile(wire(value));await h.sync();}finally{await h.close();}
}
async function frozenModule(root,relative){return import(pathToFileURL(path.join(root,DEPS,relative)).href);}
async function snarkAPI(root){
  const meta=JSON.parse((await regular(root,`${DEPS}/snarkjs/package.json`)).bytes);
  check(meta.version==='0.7.5','CONTRIBUTION_SNARKJS_VERSION_MISMATCH');
  return frozenModule(root,'snarkjs/main.js');
}

/** Full public-key contribution hashes bind every MPC point; names are provenance only. */
export async function inspectContributionChain({rootDirectory=ROOT,zkeyPath}={}){
  const root=await fs.realpath(rootDirectory);
  const [{readBinFile},{readHeader,readMPCParams,hashPubKey},{default:Blake2b}]=await Promise.all([
    frozenModule(root,'@iden3/binfileutils/src/binfileutils.js'),
    frozenModule(root,'snarkjs/src/zkey_utils.js'),frozenModule(root,'blake2b-wasm/index.js')]);
  await Blake2b.ready();let fd,curve;
  try{
    const binary=await readBinFile(zkeyPath,'zkey',2);fd=binary.fd;
    const header=await readHeader(fd,binary.sections,false,{singleThread:true});curve=header.curve;
    check(header.protocol==='groth16','CONTRIBUTION_PROTOCOL_INVALID');
    const mpc=await readMPCParams(fd,curve,binary.sections);
    check(mpc.contributions.length<=10000,'CONTRIBUTION_CHAIN_TOO_LONG');
    return mpc.contributions.map(c=>{
      const hasher=Blake2b(64);hashPubKey(hasher,curve,c);
      return {type:c.type,name:c.name??'',transcriptHex:'0x'+Buffer.from(c.transcript).toString('hex'),
        contributionHashHex:'0x'+Buffer.from(hasher.digest()).toString('hex'),
        ...(c.type===1?{beaconHash:'0x'+Buffer.from(c.beaconHash).toString('hex'),numIterationsExp:c.numIterationsExp}:{})};
    });
  }finally{await fd?.close();await curve?.terminate();}
}

export function validateContributionContinuation(before,after,{name}={}){
  check(validName(name),'CONTRIBUTION_OPERATOR_NAME_INVALID');
  check(Array.isArray(before)&&Array.isArray(after)&&before.length<10000&&after.length===before.length+1,'CONTRIBUTION_APPEND_LENGTH_INVALID');
  check(before.every(c=>c.type===0&&typeof c.name==='string'&&c.name.length>0&&/^0x[0-9a-f]{128}$/.test(c.contributionHashHex??'')),
    'CONTRIBUTION_INPUT_CHAIN_INVALID');
  check(new Set(before.map(c=>c.name)).size===before.length&&!before.some(c=>c.name===name),'CONTRIBUTION_OPERATOR_ALREADY_PRESENT');
  check(isDeepStrictEqual(after.slice(0,-1),before),'CONTRIBUTION_PREFIX_CHANGED');
  const added=after.at(-1);
  check(added.type===0&&added.name===name&&/^0x[0-9a-f]{128}$/.test(added.contributionHashHex??'')&&
    /^0x[0-9a-f]{128}$/.test(added.transcriptHex??''),'CONTRIBUTION_ADDED_RECORD_INVALID');
  return {previousCount:before.length,contributionCount:after.length,fullPublicKeyHashPrefixPreserved:true,
    name,independentOperatorIdentityAuthenticated:false};
}

/** Generic primitive used by the frozen-production wrapper and test-only fixtures. */
export async function contributeVerifiedKey({rootDirectory=ROOT,inputZkey,outputZkey,r1cs,ptau,name,onStage=()=>{},logger}={}){
  check(validName(name),'CONTRIBUTION_OPERATOR_NAME_INVALID');const root=await fs.realpath(rootDirectory);
  for(const filename of [inputZkey,r1cs,ptau]){
    const st=await fs.lstat(filename);check(st.isFile()&&!st.isSymbolicLink()&&await fs.realpath(filename)===filename,'CONTRIBUTION_REGULAR_FILE_REQUIRED');
  }
  const parent=path.dirname(outputZkey);check(await fs.realpath(parent)===parent,'CONTRIBUTION_OUTPUT_DIRECTORY_INVALID');
  try{await fs.lstat(outputZkey);throw Object.assign(new Error('CONTRIBUTION_OUTPUT_EXISTS'),{code:'CONTRIBUTION_OUTPUT_EXISTS'});}catch(e){if(e.code!=='ENOENT')throw e;}
  const {zKey}=await snarkAPI(root),quiet=logger??{info(){},debug(){},warn(){},error(){}};
  // snarkjs 0.7.5's verifyFromInit same-ratio helper leaves a ptau handle open.
  // Public bytes avoid that file-handle GC error on current Node releases.
  const ptauBytes=await fs.readFile(ptau);
  onStage('verify-input');
  check(await zKey.verifyFromR1cs(r1cs,ptauBytes,inputZkey,quiet)===true,'CONTRIBUTION_INPUT_MATH_FAILED');
  const before=await inspectContributionChain({rootDirectory:root,zkeyPath:inputZkey});
  check(before.every(c=>c.type===0)&&!before.some(c=>c.name===name),'CONTRIBUTION_INPUT_HAS_BEACON_OR_DUPLICATE_OPERATOR');
  const inputSHA256=sha(await fs.readFile(inputZkey));
  // snarkjs writes with truncation internally. Isolate its output, then publish via
  // link(2), which fails atomically if the requested public output already exists.
  const stage=await fs.mkdtemp(path.join(parent,'.contribution-work-')),temporary=path.join(stage,'response.zkey');
  let entropyBytes,entropy;
  try{
    onStage('contribute');entropyBytes=randomBytes(64);entropy=entropyBytes.toString('hex');
    const contributionHash=await zKey.contribute(inputZkey,temporary,name,entropy,quiet);
    entropyBytes.fill(0);entropy=undefined;
    onStage('verify-output');
    check(await zKey.verifyFromR1cs(r1cs,ptauBytes,temporary,quiet)===true,'CONTRIBUTION_OUTPUT_MATH_FAILED');
    const after=await inspectContributionChain({rootDirectory:root,zkeyPath:temporary});
    const continuation=validateContributionContinuation(before,after,{name});
    check(after.at(-1).contributionHashHex==='0x'+Buffer.from(contributionHash).toString('hex'),'CONTRIBUTION_RETURNED_HASH_MISMATCH');
    check(sha(await fs.readFile(inputZkey))===inputSHA256,'CONTRIBUTION_INPUT_CHANGED');
    await fs.link(temporary,outputZkey);await fs.chmod(outputZkey,0o644);
    return {inputSHA256,outputSHA256:sha(await fs.readFile(outputZkey)),contributions:after,continuation,
      inputMathematicallyVerified:true,outputMathematicallyVerified:true,entropyPersisted:false,
      secureMemoryErasureGuaranteed:false};
  }finally{entropyBytes?.fill(0);entropy=undefined;await fs.rm(stage,{recursive:true,force:true});}
}

async function worker({root,name,inputZkey,outputZkey,r1cs,ptau}){
  try{
    const logger={info:message=>process.stdout.write(String(message)+'\n'),debug(){},warn:message=>process.stdout.write(String(message)+'\n'),error(){}};
    const result=await contributeVerifiedKey({rootDirectory:root,name,inputZkey,outputZkey,r1cs,ptau,logger});
    process.stdout.write(wire({workerSucceeded:true,...result}));
  }finally{if(globalThis.curve_bn128){await globalThis.curve_bn128.terminate();globalThis.curve_bn128=undefined;}}
}
async function executeWorker(root,options,logPath){
  const logfile=path.join(root,logPath),log=await fs.open(logfile,'wx',0o644);
  try{
    await new Promise((resolve,reject)=>{
      const env={...process.env};delete env.NODE_OPTIONS;
      const child=spawn(process.execPath,[SELF,'--internal-worker',JSON.stringify(options)],{cwd:root,env,stdio:['ignore',log.fd,log.fd]});
      const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Object.assign(new Error('CONTRIBUTION_WORKER_TIMEOUT'),{code:'CONTRIBUTION_WORKER_TIMEOUT'}));},1200000);
      child.once('error',error=>{clearTimeout(timer);reject(error);});
      child.once('exit',code=>{clearTimeout(timer);code===0?resolve():reject(Object.assign(new Error('CONTRIBUTION_WORKER_FAILED'),{code:'CONTRIBUTION_WORKER_FAILED'}));});
    });
    await log.sync();return describe(await regular(root,logPath));
  }finally{await log.close();}
}

export async function contributeProductionCeremony({execute=false,rootDirectory=ROOT,name='local-operator',inputReceiptPath=null,
  expectedInputReceiptSHA256=null,outputDirectory=null,onStage=()=>{}}={}){
  check(validName(name),'CONTRIBUTION_OPERATOR_NAME_INVALID');const root=await fs.realpath(rootDirectory);
  const freezeFile=await regular(root,FREEZE),freeze=JSON.parse(freezeFile.bytes),checked=await verifyCeremonyFreeze(freeze,{rootDirectory:root});
  check(freeze.activeMode==='asp'&&freeze.inputs.tools.snarkjsVersion==='0.7.5','CONTRIBUTION_FROZEN_MODE_INVALID');
  let previous=null,previousDescriptor=null;
  if(inputReceiptPath!==null){
    const inputReceipt=await regular(root,inputReceiptPath);previousDescriptor=describe(inputReceipt);
    check(typeof expectedInputReceiptSHA256==='string'&&/^[0-9a-f]{64}$/.test(expectedInputReceiptSHA256)&&
      previousDescriptor.sha256===expectedInputReceiptSHA256,'CONTRIBUTION_INPUT_RECEIPT_HASH_MISMATCH');
    previous=JSON.parse(inputReceipt.bytes);
    check(previous.schema==='phase2-production-contribution-receipt/v1'&&previous.executed===true&&
      previous.freezeSHA256===checked.freezeSHA256&&previous.circuits,'CONTRIBUTION_INPUT_RECEIPT_INVALID');
  }else check(expectedInputReceiptSHA256===null,'CONTRIBUTION_INPUT_RECEIPT_REQUIRED');
  outputDirectory??=`artifacts/phase2-ceremony/contributions/${name}`;publicPath(outputDirectory);
  check(/^artifacts\/phase2-ceremony\/contributions\/[a-z][a-z0-9-]{2,63}$/.test(outputDirectory),'CONTRIBUTION_OUTPUT_SCOPE_INVALID');
  const inputs={};
  for(const circuit of NAMES){
    const directory=`protocol/phase2-mainnet/build/${circuit}`,baseline=freeze.models.asp.circuits[circuit];
    const initial=JSON.parse((await regular(root,`${directory}/initial-challenge.json`)).bytes);
    check(initial.schema==='phase2-production-initial-challenge/v1'&&initial.circuit===circuit&&initial.freezeSHA256===checked.freezeSHA256&&
      initial.initialOnly===true&&initial.contributions===0,'CONTRIBUTION_INITIAL_DESCRIPTOR_INVALID');
    const r1cs=await regular(root,`${directory}/main.r1cs`),wasm=await regular(root,`${directory}/main_js/main.wasm`);
    check(sha(r1cs.bytes)===baseline.baselineDevelopmentArtifacts.find(f=>f.path.endsWith('.r1cs')).sha256&&
      sha(wasm.bytes)===baseline.baselineDevelopmentArtifacts.find(f=>f.path.endsWith('.wasm')).sha256,'CONTRIBUTION_APPROVED_COMPUTATION_MISMATCH');
    const expected=previous?previous.circuits[circuit]?.output:initial.artifacts.initialZkey;
    check(expected&&typeof expected.path==='string'&&/^[0-9a-f]{64}$/.test(expected.sha256),'CONTRIBUTION_EXPECTED_KEY_REQUIRED');
    const input=await regular(root,expected.path);
    check(sha(input.bytes)===expected.sha256&&input.bytes.length===expected.bytes,'CONTRIBUTION_INPUT_HASH_MISMATCH');
    const contributions=await inspectContributionChain({rootDirectory:root,zkeyPath:input.absolute});
    check(contributions.every(c=>c.type===0)&&!contributions.some(c=>c.name===name),'CONTRIBUTION_INPUT_HAS_BEACON_OR_DUPLICATE_OPERATOR');
    if(previous)check(isDeepStrictEqual(contributions,previous.circuits[circuit].contributions),'CONTRIBUTION_RECEIPT_CHAIN_MISMATCH');
    else check(contributions.length===0,'CONTRIBUTION_INITIAL_KEY_ALREADY_CONTRIBUTED');
    inputs[circuit]={input:describe(input),r1cs:describe(r1cs),wasm:describe(wasm),contributions,
      outputPath:`${outputDirectory}/${circuit}.zkey`};
  }
  const report={schema:'phase2-production-contribution-receipt/v1',createdAtUTC:new Date().toISOString(),executed:false,
    freezePath:FREEZE,freezeSHA256:checked.freezeSHA256,chainId:4663,policyMode:'asp',snarkjsVersion:'0.7.5',
    operator:name,sameOperatorForBothCircuits:true,independentOperatorIdentityAuthenticated:false,independentOperatorCountEstablished:false,
    entropyPersisted:false,entropyInArguments:false,entropyInLogs:false,secureMemoryErasureGuaranteed:false,
    productionReady:false,transactionsBroadcast:0,previousReceipt:previousDescriptor,
    ptau:freeze.inputs.ptau,circuits:inputs,outputDirectory,receiptPath:`${outputDirectory}/receipt.json`,
    limitations:['One operator contributes to both circuits. Multiple labels or repeated runs do not establish independent participants.',
      'Names and receipts do not authenticate operator identity. Confirm the input receipt hash through an independent channel.',
      'Entropy is generated inside a dedicated child process and never written; JavaScript memory or OS swap erasure is not guaranteed.',
      'A later independent contribution and precommitted public beacon are still required. This is not a final parameter manifest.']};
  if(!execute)return report;
  const base=path.join(root,'protocol/phase2-mainnet'),lockFile=path.join(base,'.contribute.lock');
  check(await fs.realpath(base)===base,'CONTRIBUTION_LOCK_DIRECTORY_INVALID');const lock=await fs.open(lockFile,'wx',0o600);
  try{
    const out=path.join(root,outputDirectory),parent=path.dirname(out);await fs.mkdir(parent,{recursive:true});
    check(await fs.realpath(parent)===parent,'CONTRIBUTION_OUTPUT_DIRECTORY_INVALID');
    try{await fs.mkdir(out,{recursive:false,mode:0o755});}catch(error){if(error.code==='EEXIST')throw Object.assign(new Error('CONTRIBUTION_OUTPUT_EXISTS'),{code:'CONTRIBUTION_OUTPUT_EXISTS'});throw error;}
    const ptau=path.join(root,freeze.inputs.ptau.path);
    for(const circuit of NAMES){
      onStage(`${circuit}:verify-input-contribute-verify-output`);const row=inputs[circuit];
      const log=await executeWorker(root,{root,name,inputZkey:path.join(root,row.input.path),outputZkey:path.join(root,row.outputPath),
        r1cs:path.join(root,row.r1cs.path),ptau},`${outputDirectory}/${circuit}.log`);
      const output=await regular(root,row.outputPath),contributions=await inspectContributionChain({rootDirectory:root,zkeyPath:output.absolute});
      const continuation=validateContributionContinuation(row.contributions,contributions,{name});
      report.circuits[circuit]={...row,output:describe(output),contributions,continuation,log,
        inputMathematicallyVerified:true,outputMathematicallyVerified:true};
    }
    await verifyCeremonyFreeze(freeze,{rootDirectory:root});
    for(const row of Object.values(inputs))check(sha((await regular(root,row.input.path)).bytes)===row.input.sha256,'CONTRIBUTION_INPUT_CHANGED');
    if(previousDescriptor)check(sha((await regular(root,previousDescriptor.path)).bytes)===previousDescriptor.sha256,'CONTRIBUTION_RECEIPT_CHANGED');
    report.executed=true;await freshJSON(path.join(root,report.receiptPath),report);return report;
  }finally{await lock.close();await fs.unlink(lockFile);}
}

if(process.argv[1]&&path.resolve(process.argv[1])===SELF){
  try{
    const args=process.argv.slice(2);
    if(args[0]==='--internal-worker'){
      check(args.length===2,'CONTRIBUTION_WORKER_ARGUMENTS_INVALID');await worker(JSON.parse(args[1]));
    }else{
      const options={execute:false};let modeSeen=false;
      while(args.length){const flag=args.shift();
        if(['--plan','--contribute'].includes(flag)){check(!modeSeen,'CONTRIBUTION_MODE_DUPLICATE');modeSeen=true;options.execute=flag==='--contribute';}
        else{const field={'--name':'name','--input-receipt':'inputReceiptPath','--expected-input-receipt-sha256':'expectedInputReceiptSHA256','--output-directory':'outputDirectory'}[flag];
          check(field&&args.length>0&&!Object.hasOwn(options,field),'USAGE_CONTRIBUTION_PLAN_OR_CONTRIBUTE');options[field]=args.shift();}
      }
      const result=await contributeProductionCeremony({...options,onStage:stage=>process.stderr.write(stage+'\n')});
      console.log(wire(result));
    }
  }catch(error){console.error(wire({error:error.code??error.message,finalParametersCreated:false,transactionsBroadcast:0}));process.exitCode=1;}
}
