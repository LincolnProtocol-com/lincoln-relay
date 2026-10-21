#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Offline inventory and command generation only. Never runs setup or reads entropy.
import fs from 'node:fs/promises';
import {createReadStream,constants} from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const DEPS='scripts/private-transfer/deps';
const PTAU='vendor/nocturne-protocol/packages/circuits/data/powersOfTau28_hez_final_15.ptau';
const PTAU_SHA='3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f';
const PTAU_BLAKE='982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e';
const NAMES=['joinsplit','holder-exit'];
const INPUT_NAMES={joinsplit:['root','publicIn','publicOut','context','scope','inputNullifiers[0]','inputNullifiers[1]','outputCommitments[0]','outputCommitments[1]'],
  'holder-exit':['commitment','nullifier','value','scope','context']};
const wire=x=>JSON.stringify(x,null,2)+'\n';
const hash=x=>createHash('sha256').update(typeof x==='string'?x:JSON.stringify(x)).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const need=(x,code)=>{if(!x)fail(code);};
const relative=root=>file=>path.relative(root,file).split(path.sep).join('/');
const quote=value=>"'"+String(value).replaceAll("'","'\\''")+"'";

function publicRelative(value){
  need(typeof value==='string'&&value.length>0&&!path.isAbsolute(value)&&!value.includes('\\')&&value.split('/').every(s=>s&&s!=='.'&&s!=='..'&&!s.startsWith('.')),'CEREMONY_PUBLIC_PATH_REQUIRED');return value;
}
function outputRelative(value){publicRelative(value);need(value.startsWith('artifacts/phase2-ceremony/')&&value.endsWith('/freeze.json'),'CEREMONY_FREEZE_OUTPUT_PATH_REQUIRED');return value;}
async function publicFile(root,value){
  publicRelative(value);
  const prefixes=['protocol/phase2-asp/circuits/','protocol/phase2-asp/generated/','protocol/phase2/circuits/','protocol/phase2-routes/circuits/',
    'artifacts/phase2-asp/circuits/','artifacts/phase2-ceremony/',`${DEPS}/`];
  const exact=['scripts/phase2-asp/build-circuits.mjs','scripts/phase2-routes/build-circuits.mjs','scripts/phase2/build-circuits.mjs','scripts/phase2-ceremony/prepare.mjs',PTAU];
  need(prefixes.some(prefix=>value.startsWith(prefix))||exact.includes(value),'CEREMONY_INPUT_OUTSIDE_PUBLIC_SCOPE');
  const absolute=path.join(root,value),stat=await fs.lstat(absolute);
  need(stat.isFile()&&!stat.isSymbolicLink()&&await fs.realpath(absolute)===absolute,'CEREMONY_REGULAR_PUBLIC_FILE_REQUIRED');return {absolute,stat};
}
async function descriptor(root,value,{blake=false}={}){
  const {absolute,stat}=await publicFile(root,value),sha=createHash('sha256'),b=blake?createHash('blake2b512'):null;
  for await(const chunk of createReadStream(absolute)){sha.update(chunk);b?.update(chunk);}
  return {path:value,bytes:stat.size,sha256:sha.digest('hex'),...(b?{blake2b512:b.digest('hex')}:{})};
}
async function readJSON(root,value){const {absolute,stat}=await publicFile(root,value);need(stat.size<=4*1024*1024,'CEREMONY_JSON_TOO_LARGE');return JSON.parse(await fs.readFile(absolute,'utf8'));}
async function tree(root,directory,{extension=null}={}){
  publicRelative(directory);const absolute=path.join(root,directory);need(await fs.realpath(absolute)===absolute,'CEREMONY_SOURCE_DIRECTORY_SYMLINK');
  const files=[];
  for(const entry of await fs.readdir(absolute,{withFileTypes:true})){
    if(entry.name.startsWith('.'))continue;
    need(!entry.isSymbolicLink(),'CEREMONY_DEPENDENCY_SYMLINK');const name=directory+'/'+entry.name;
    if(entry.isDirectory())files.push(...await tree(root,name,{extension}));
    else if(entry.isFile()&&(!extension||entry.name.endsWith(extension)))files.push(name);
  }
  return files.sort();
}
async function describeAll(root,files){
  const out=new Array(files.length);let index=0;
  await Promise.all(Array.from({length:Math.min(6,files.length)},async()=>{for(;;){const i=index++;if(i>=files.length)return;out[i]=await descriptor(root,files[i]);}}));return out;
}
const setSummary=files=>({fileCount:files.length,totalBytes:files.reduce((n,f)=>n+f.bytes,0),sha256:hash(files),files});

export async function inspectCeremonyPreparation({rootDirectory=ROOT,mode='asp'}={}){
  need(['asp','permissionless'].includes(mode),'CEREMONY_MODE_INVALID');const root=await fs.realpath(rootDirectory);
  const report={schema:'phase2-ceremony-freeze/v1',activeMode:mode,createdAtUTC:new Date().toISOString(),offline:true,readOnly:true,
    setupExecuted:false,contributionsExecuted:false,entropyRead:false,entropyPersisted:false,transactionsBroadcast:0,productionReady:false,deploymentPermitted:false,
    protocol:'groth16',curve:'bn128',inputs:{},models:{},blockers:[],
    productionTargets:{build:'artifacts/phase2-mainnet/contracts.json',circuits:Object.fromEntries(NAMES.map(name=>[name,{directory:`protocol/phase2-mainnet/build/${name}`,
      manifest:`protocol/phase2-mainnet/build/${name}/manifest.json`,rawVerifier:`protocol/phase2-mainnet/build/${name}/Groth16Verifier.sol`} ])),generatedVerifierDirectory:'protocol/phase2-mainnet/generated/'},
    assumptions:['The user selected a self-hosted current-note ASP. Removing it later changes the circuit/policy freeze.',
      'Public proving keys and ceremony transcripts contain no wallet seed or private note witness; this inventory does not read wallet directories.',
      'Hashes establish byte identity, not correctness, honest entropy destruction, contributor independence, or an independent security audit.',
      'Multiple agents or labels on the same host/operator do not constitute independent contributors.',
      'This script never executes generated commands. Initial setup keys, development keys and inventory output are not production-ready parameters.'],
    sources:[{url:'https://github.com/iden3/snarkjs/blob/v0.7.5/README.md',purpose:'Groth16 per-circuit setup, contributions, verification, beacon and public ptau checksums'},
      {url:'https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau',purpose:'Published power-15 prepared Phase-1 transcript'}]};
  const compilerMeta=await readJSON(root,`${DEPS}/node_modules/circom2/package.json`),snarkMeta=await readJSON(root,`${DEPS}/node_modules/snarkjs/package.json`),libMeta=await readJSON(root,`${DEPS}/node_modules/circomlib/package.json`);
  need(compilerMeta.version==='0.2.22'&&snarkMeta.version==='0.7.5'&&libMeta.version==='2.0.5','CEREMONY_TOOL_VERSION_MISMATCH');
  const dependencyFiles=await tree(root,`${DEPS}/node_modules`);
  report.inputs.installedDependencies=setSummary(await describeAll(root,dependencyFiles));
  report.inputs.projectTools=await describeAll(root,[`${DEPS}/package.json`,`${DEPS}/package-lock.json`,'scripts/phase2-asp/build-circuits.mjs','scripts/phase2-routes/build-circuits.mjs','scripts/phase2/build-circuits.mjs','scripts/phase2-ceremony/prepare.mjs']);
  report.inputs.tools={circomPackage:'0.2.22',circomCompilerVersionClaim:'2.2.2',compilerVersionNotExecuted:true,snarkjsVersion:'0.7.5',circomlibVersion:'2.0.5',
    compilerEntrypoint:`${DEPS}/node_modules/circom2/cli.js`,compilerWasm:`${DEPS}/node_modules/circom2/circom.wasm`,snarkjsEntrypoint:`${DEPS}/node_modules/snarkjs/build/cli.cjs`,
    optimization:'O2',includeDirectories:[`${DEPS}/node_modules`],runtime:{nodeVersion:process.version,platform:process.platform,architecture:process.arch,
      independentlyReproducibleAcrossPlatformsNotEstablished:true}};
  const binary=await fs.realpath(process.execPath),runtimeHash=createHash('sha256');for await(const chunk of createReadStream(binary))runtimeHash.update(chunk);
  report.inputs.tools.runtime.executableSHA256=runtimeHash.digest('hex');
  report.inputs.ptau={...await descriptor(root,PTAU,{blake:true}),power:15,publishedSHA256:PTAU_SHA,publishedBlake2b512:PTAU_BLAKE,
    cryptographicVerificationExecuted:false,publishedChecksumMatches:false};
  const tau=report.inputs.ptau;tau.publishedChecksumMatches=tau.bytes===37831832&&tau.sha256===PTAU_SHA&&tau.blake2b512===PTAU_BLAKE;
  need(tau.publishedChecksumMatches,'CEREMONY_PTAU_DIGEST_MISMATCH');
  const circuits={};
  for(const name of NAMES){
    const sourceDirectory=`protocol/phase2-asp/circuits/${name}`,files=await describeAll(root,await tree(root,sourceDirectory,{extension:'.circom'}));
    const manifestPath=`artifacts/phase2-asp/circuits/${name}/manifest.json`,manifest=await readJSON(root,manifestPath);
    need(manifest.testOnly===true&&manifest.productionReady===false&&manifest.inputs?.circuit===name,'CEREMONY_BASELINE_MANIFEST_INVALID');
    need(JSON.stringify(manifest.inputs.sources)===JSON.stringify(files),'CEREMONY_BASELINE_SOURCE_DRIFT');
    need(manifest.inputs.compilerPackageVersion==='0.2.22'&&manifest.inputs.snarkjsVersion==='0.7.5'&&manifest.inputs.circomlibVersion==='2.0.5','CEREMONY_BASELINE_TOOLS_DRIFT');
    const publicArtifactReferences=Object.values(manifest.artifacts).map(row=>row.path);const artifacts=await describeAll(root,publicArtifactReferences);
    for(const entry of artifacts)need(Object.values(manifest.artifacts).some(row=>row.path===entry.path&&row.sha256===entry.sha256),'CEREMONY_DEVELOPMENT_ARTIFACT_DRIFT');
    circuits[name]={name,sourceDirectory,main:`${sourceDirectory}/main.circom`,sources:setSummary(files),baselineManifest:await descriptor(root,manifestPath),
      baselineDevelopmentArtifacts:artifacts,baselineCounts:manifest.counts,baselineRequiredPower:manifest.requiredPower,publicSignalNames:INPUT_NAMES[name],
      maxTreeDepth:name==='joinsplit'?20:null,productionCompileExecuted:false,productionR1csNotYetFrozen:true,developmentKeyReusePermitted:false};
  }
  const comparison={};
  for(const [key,directory] of [['basic','protocol/phase2/circuits'],['routed','protocol/phase2-routes/circuits']]){
    const files=await describeAll(root,await tree(root,directory,{extension:'.circom'}));comparison[key]={sources:setSummary(files),main:`${directory}/main.circom`,candidateSelected:false};
  }
  report.inputs.circomlib=setSummary(report.inputs.installedDependencies.files.filter(row=>row.path.startsWith(`${DEPS}/node_modules/circomlib/circuits/`)&&row.path.endsWith('.circom')));
  for(const circuit of Object.values(circuits)){
    const m=await readJSON(root,circuit.baselineManifest.path);need(m.inputs.circomlibSourceSetSHA256===report.inputs.circomlib.sha256,'CEREMONY_CIRCOMLIB_BASELINE_DRIFT');
    for(const [field,file] of [['compilerEntrypointSHA256',report.inputs.tools.compilerEntrypoint],['compilerWasmSHA256',report.inputs.tools.compilerWasm]]){
      need(report.inputs.installedDependencies.files.find(row=>row.path===file)?.sha256===m.inputs[field],'CEREMONY_COMPILER_BASELINE_DRIFT');
    }
    need(report.inputs.projectTools.find(row=>row.path===`${DEPS}/package-lock.json`)?.sha256===m.inputs.dependencyLockSHA256,'CEREMONY_LOCK_BASELINE_DRIFT');
  }
  report.models.asp={policy:'self-hosted-current-note-membership',circuits,sourceSetFrozen:true,productionCompilationRequired:true,
    circuitSemantics:['JoinSplit proves both positive input notes are current ASP members and binds root/epoch/validUntil to context.',
      'Normal JoinSplit publicIn is constrained to zero; public funding uses depositDynamic.',
      'Holder exit deliberately requires no ASP membership and shares the JoinSplit nullifier.',
      'Factorized commitments support measured-output routing and receipt recovery.'],
    requiredExternalEvidence:['Review and freeze circuit/contract domains and full public-input binding before running setup.',
      'Recompile in the production directory and pin resulting r1cs/wasm; development manifests provide comparison only.',
      'Verify the published ptau cryptographically, not just its checksum.',
      'Obtain actual independent contributions and per-step verification; no identity or entropy-destruction attestation is fabricated.']};
  report.models.permissionless={policy:'candidate-only-not-selected',candidateReady:false,productionCommandsAvailable:false,comparison,
    requirements:['A new factorized candidate must remove current-note ASP membership and its policy context, not merely stop the ASP HTTP service.',
      'Preserve depositDynamic and measured-output DEX routing, holder-exit/shared nullifier and recovery.',
      'Decide whether publicIn remains zero/depositDynamic-only and bind the selected rule in contract, circuit and SDK.',
      'Define and freeze the new pool/profile domains, context hash, verifier interface and SDK before any ceremony.',
      'The older basic Phase2 circuit uses a different note model; the routed comparison is closer but is not a complete replacement for the current ASP pool with public exits.'],
    reason:'No separately reviewed permissionless production candidate exists. Choosing the old test circuit would silently discard current behavior.'};
  report.commandsAvailable=mode==='asp';
  if(mode==='permissionless')report.blockers.push({code:'PERMISSIONLESS_CANDIDATE_NOT_READY',detail:report.models.permissionless.reason});
  report.blockers.push({code:'PRODUCTION_R1CS_NOT_FROZEN',detail:'Inventory freezes source and tools only; generated production r1cs/wasm must be compiled and independently checked before initial setup.'});
  report.blockers.push({code:'CEREMONY_NOT_EXECUTED',detail:'No production contribution, final key, beacon or cryptographic transcript verification was executed.'});
  report.freezeSHA256=freezeDigest(report);return report;
}
function freezeDigest(report){const copy={...report};delete copy.freezeSHA256;return hash(copy);}

export async function verifyCeremonyFreeze(freeze,{rootDirectory=ROOT}={}){
  const root=await fs.realpath(rootDirectory);need(freeze?.schema==='phase2-ceremony-freeze/v1'&&freeze.freezeSHA256===freezeDigest(freeze),'CEREMONY_FREEZE_DIGEST_MISMATCH');
  need(freeze.setupExecuted===false&&freeze.productionReady===false&&freeze.deploymentPermitted===false,'CEREMONY_ASSURANCE_SCOPE_INVALID');
  need(['asp','permissionless'].includes(freeze.activeMode)&&freeze.inputs?.installedDependencies?.fileCount>0&&freeze.models?.asp?.circuits?.joinsplit&&
    freeze.models.asp.circuits['holder-exit']&&freeze.models?.permissionless?.candidateReady===false,'CEREMONY_FREEZE_STRUCTURE_INVALID');
  const samePaths=(current,frozen)=>JSON.stringify(current)===JSON.stringify(frozen.map(row=>row.path));
  need(samePaths(await tree(root,`${DEPS}/node_modules`),freeze.inputs.installedDependencies.files),'CEREMONY_DEPENDENCY_FILE_SET_CHANGED');
  for(const circuit of Object.values(freeze.models.asp.circuits))need(samePaths(await tree(root,circuit.sourceDirectory,{extension:'.circom'}),circuit.sources.files),'CEREMONY_SOURCE_FILE_SET_CHANGED');
  for(const comparison of Object.values(freeze.models.permissionless.comparison))need(samePaths(await tree(root,path.dirname(comparison.main),{extension:'.circom'}),comparison.sources.files),'CEREMONY_SOURCE_FILE_SET_CHANGED');
  const descriptors=new Map();
  function visit(value){if(Array.isArray(value)){for(const row of value)visit(row);return;}if(!value||typeof value!=='object')return;
    if(typeof value.path==='string'&&typeof value.sha256==='string'&&typeof value.bytes==='number')descriptors.set(value.path,value);
    for(const row of Object.values(value))visit(row);}
  visit(freeze);
  const actual=await describeAll(root,[...descriptors.keys()]);
  for(const row of actual){const expected=descriptors.get(row.path);need(row.bytes===expected.bytes&&row.sha256===expected.sha256,'CEREMONY_FROZEN_INPUT_CHANGED');}
  need(freeze.inputs.ptau.sha256===PTAU_SHA&&freeze.inputs.ptau.blake2b512===PTAU_BLAKE,'CEREMONY_PTAU_DIGEST_MISMATCH');
  return {verified:true,activeMode:freeze.activeMode,filesChecked:actual.length,freezeSHA256:freeze.freezeSHA256,setupExecuted:false,cryptographicVerificationExecuted:false,
    runtimeIdentity:freeze.inputs.tools.runtime,limitation:'Recorded Node executable identity is provenance for the originating host; file verification checks the portable repository inputs, not independent build equivalence.'};
}

export function ceremonyCommands(freeze,{freezePath}={}){
  need(freeze?.schema==='phase2-ceremony-freeze/v1'&&freeze.freezeSHA256===freezeDigest(freeze),'CEREMONY_FREEZE_DIGEST_MISMATCH');
  need(freeze.activeMode==='asp'&&freeze.commandsAvailable===true,'CEREMONY_MODE_NOT_READY');publicRelative(freezePath);
  const node='node',snark=freeze.inputs.tools.snarkjsEntrypoint,compiler=freeze.inputs.tools.compilerEntrypoint,ptau=freeze.inputs.ptau.path;
  const instructions=[{id:'check-freeze',argv:[node,'scripts/phase2-ceremony/prepare.mjs','--verify',freezePath],readOnly:true},
    {id:'verify-phase1',argv:[node,snark,'powersoftau','verify',ptau],readOnly:true,savePublicLog:true}];
  for(const name of NAMES){
    const out=freeze.productionTargets.circuits[name].directory,main=freeze.models.asp.circuits[name].main,r1cs=`${out}/main.r1cs`,initial=`${out}/0000.zkey`,first=`${out}/0001.zkey`,final=`${out}/final.zkey`;
    instructions.push({id:`${name}:mkdir`,argv:['mkdir','-p',out]},
      {id:`${name}:compile`,argv:[node,compiler,main,'--r1cs','--wasm','--sym','--O2','-l',`${DEPS}/node_modules`,'-o',out],mustNotExist:[r1cs,`${out}/main_js/main.wasm`,`${out}/main.sym`],savePublicLog:true},
      {id:`${name}:review-r1cs`,argv:[node,snark,'r1cs','info',r1cs],readOnly:true,savePublicLog:true,requires:['Pin compiled r1cs and wasm hashes and independently reproduce them; compare expected public signals and constraints.']},
      {id:`${name}:initial-setup`,argv:[node,snark,'groth16','setup',r1cs,ptau,initial],mustNotExist:[initial],savePublicLog:true,requires:['Actual production r1cs/wasm freeze has been checked.'],initialKeyUnsafeForUse:true},
      {id:`${name}:contribute-template`,argv:[node,snark,'zkey','contribute',initial,first,'--name=CONTRIBUTOR_LABEL'],mustNotExist:[first],interactiveEntropy:true,
        savePublicLog:true,requires:['The contributor verifies the exact input digests and runs this on their own controlled environment. Never pass -e/--entropy or persist prompt input.']},
      {id:`${name}:verify-contribution`,argv:[node,snark,'zkey','verify',r1cs,ptau,first],readOnly:true,savePublicLog:true},
      {id:`${name}:verify-final`,argv:[node,snark,'zkey','verify',r1cs,ptau,final],readOnly:true,savePublicLog:true,
        requires:['A complete contribution chain and final beacon from the precommitted public source exist; final.zkey is not produced by these templates.']},
      {id:`${name}:export-vkey`,argv:[node,snark,'zkey','export','verificationkey',final,`${out}/verification_key.json`],mustNotExist:[`${out}/verification_key.json`]},
      {id:`${name}:export-raw-verifier`,argv:[node,snark,'zkey','export','solidityverifier',final,freeze.productionTargets.circuits[name].rawVerifier],mustNotExist:[freeze.productionTargets.circuits[name].rawVerifier],
        requires:['Mainnet builder must record any deterministic pragma/name transformation and its hashes; never silently edit a hashed final verifier.']});
  }
  return {schema:'phase2-ceremony-command-plan/v1',activeMode:'asp',freezeSHA256:freeze.freezeSHA256,commandsExecuted:false,
    productionManifestContract:productionManifestTemplates(freeze,{freezePath}),
    atomicRunnerProvided:false,operatorStageGatesRequired:true,instructions,
    beaconTemplate:{executable:false,argvTemplate:[node,snark,'zkey','beacon','LAST_VERIFIED_CONTRIBUTION.zkey','final.zkey','BEACON_FROM_PRECOMMITTED_PUBLIC_SOURCE','ITERATION_EXPONENT','--name=FINAL_BEACON'],
      requiredEvidence:['Precommit the source, round/time and iteration exponent before its randomness is known.','Publish source proof and verify the resulting final key.']},
    shellPreview:instructions.map(step=>`# ${step.id}${step.requires?' — '+step.requires.join(' '):''}\n`+
      (step.mustNotExist??[]).map(file=>`test ! -e ${quote(file)}\n`).join('')+step.argv.map(quote).join(' ')).join('\n\n'),
    warnings:['Shell preview is a human-operated template, not an unattended runner: review-r1cs, contributor handoff and beacon are deliberate separate stages.',
      'Only one illustrative contribution is shown. Independent contributors repeat with new sequential input/output filenames and verify every transition.',
      'Initial/dev parameters must not be relabelled as production, and no part of this command plan asserts contributor independence or readiness.']};
}

// Templates deliberately use a different schema and null artifact digests. They
// cannot be loaded as final parameter manifests by the mainnet builder.
export function productionManifestTemplates(freeze,{freezePath}={}){
  need(freeze?.schema==='phase2-ceremony-freeze/v1'&&freeze.freezeSHA256===freezeDigest(freeze),'CEREMONY_FREEZE_DIGEST_MISMATCH');
  need(freeze.activeMode==='asp'&&freeze.commandsAvailable===true,'CEREMONY_MODE_NOT_READY');publicRelative(freezePath);
  const names={joinsplit:'Phase2ASPJoinSplitVerifier','holder-exit':'Phase2ASPExitVerifier'},templates={},transcriptTemplates={};
  for(const name of NAMES){
    const baseline=freeze.models.asp.circuits[name],out=freeze.productionTargets.circuits[name].directory;
    const byExtension=extension=>baseline.baselineDevelopmentArtifacts.find(row=>row.path.endsWith(extension));
    const r1cs=byExtension('.r1cs'),wasm=byExtension('.wasm'),developmentKey=byExtension('.dev.zkey');
    need(r1cs&&wasm&&developmentKey,'CEREMONY_APPROVED_INPUTS_REQUIRED');
    templates[name]={schema:'phase2-asp-production-circuits-template/v1',requiredFinalSchema:'phase2-asp-production-circuits/v1',
      templateOnly:true,finalManifestPath:freeze.productionTargets.circuits[name].manifest,mode:'asp',policyMode:'asp',targetChainId:4663,allowedChainIds:[4663],
      protocol:'groth16',curve:'bn128',testOnly:false,productionReady:false,
      inputs:{circuit:name,policyMode:'asp',maxTreeDepth:baseline.maxTreeDepth,publicSignalNames:baseline.publicSignalNames,sources:baseline.sources.files,
        sourceSetSHA256:baseline.sources.sha256,optimization:freeze.inputs.tools.optimization,compilerPackageVersion:freeze.inputs.tools.circomPackage,
        snarkjsVersion:freeze.inputs.tools.snarkjsVersion,circomlibVersion:freeze.inputs.tools.circomlibVersion},
      counts:baseline.baselineCounts,
      artifacts:{r1cs:{path:`${out}/main.r1cs`,sha256:null},wasm:{path:`${out}/main_js/main.wasm`,sha256:null},
        zkey:{path:`${out}/final.zkey`,sha256:null},vkey:{path:`${out}/verification_key.json`,sha256:null},
        verifier:{path:`protocol/phase2-mainnet/generated/${names[name]}.sol`,sha256:null},
        ceremonyTranscript:{path:`${out}/ceremony-transcript.json`,sha256:null}},
      phase1:{path:freeze.inputs.ptau.path,sha256:freeze.inputs.ptau.sha256,power:freeze.inputs.ptau.power},
      setup:{kind:'multi-party-phase2',status:'not-executed',contributions:[],verifyFromR1cs:false,independentOperatorIdentityAuthenticated:false},
      productionParameterAttestation:{status:'not-produced',productionZkeyCreated:false,contributionChainVerified:false,finalBeaconVerified:false,
        independentContributorsAuthenticated:false,developmentKeyReusePermitted:false},
      freeze:{path:freezePath,freezeSHA256:freeze.freezeSHA256},
      expectedCompiledInputs:{r1cs:{sha256:r1cs.sha256,bytes:r1cs.bytes},wasm:{sha256:wasm.sha256,bytes:wasm.bytes},
        forbiddenDevelopmentZkeySHA256:developmentKey.sha256,
        rule:'Current approved sources and R1CS/WASM must match the verified ASP baseline byte for byte. Changed computation requires a new reviewed freeze and builder policy; do not change the expected hashes to bypass a mismatch.'},
      verifierExport:{rawSource:`${out}/Groth16Verifier.sol`,contractName:names[name],builder:'scripts/phase2-mainnet/build.mjs#canonicalProductionVerifier',
        transformations:[{from:'pragma solidity >=0.7.0 <0.9.0;',to:'pragma solidity 0.8.28;'},
          {from:'contract Groth16Verifier {',to:`contract ${names[name]} {`}],extraBannerPermitted:false},
      completionInstructions:['This is an incomplete template, not a production parameter attestation. Keep it under a .template.json filename.',
        'Reproduce and compare approved R1CS/WASM before initial setup. Public compiled assets may match the baseline; the final zkey must differ from the development key.',
        'Complete the actual independent contribution chain, predetermined beacon and zkey verification; publish all public input/output hashes and verification logs.',
        'Export the verification key and raw Solidity verifier from the actual final zkey, apply only the recorded deterministic verifier transformations, then hash the exact resulting files.',
        'Extract contributions from the actual final zkey binary section 10 using readEmbeddedMPC; publish a ceremony-transcript.json bound to r1csSHA256, ptauSHA256 and finalZkeySHA256. Its contributions array must equal the extracted entries exactly, including type/name/transcriptHex and final beacon parameters.',
        'Create a new final manifest at finalManifestPath with requiredFinalSchema only when all six artifacts really exist and each null sha256 has been replaced by its actual digest. Do not claim independent identities merely from labels.',
        'The mainnet builder rechecks approved source/R1CS/WASM binding, rejects the development zkey, checks at least two distinct named type-0 contributions plus a final type-1 beacon in the real zkey, binds the transcript, verifies final zkey from R1CS/ptau and compares the exported vkey and exact canonical verifier. This still does not authenticate operator independence or constitute an audit.']};
    transcriptTemplates[name]={schema:'phase2-asp-ceremony-transcript-template/v1',requiredFinalSchema:'phase2-asp-ceremony-transcript/v1',templateOnly:true,
      finalTranscriptPath:`${out}/ceremony-transcript.json`,circuit:name,r1csSHA256:r1cs.sha256,ptauSHA256:freeze.inputs.ptau.sha256,finalZkeySHA256:null,
      contributions:null,independentOperatorIdentityAuthenticated:false,
      contributionSource:'scripts/phase2-mainnet/build.mjs#readEmbeddedMPC reads actual final zkey binary section 10; copy its complete array without replacing entries by labels.',
      embeddedRecordContract:{nonBeacon:{type:0,requiredFields:['type','name','transcriptHex'],minimumEntries:2,distinctNonEmptyNames:true,
        transcriptHexEncoding:'0x followed by the exact 64-byte embedded contribution transcript'},
        finalBeacon:{type:1,requiredFields:['type','name','transcriptHex','beaconHash','numIterationsExp'],mustBeLast:true,numIterationsExpRange:[10,63],
          beaconHashEncoding:'0x-prefixed bytes exactly as embedded, not a guessed/example beacon'}},
      completionInstructions:['Do not produce a final transcript or fill participant entries before the real ceremony exists.',
        'The final schema, circuit name, approved R1CS hash, pinned ptau hash and actual final zkey hash are required.',
        'The contributions array must be a deep exact match to readEmbeddedMPC(final.zkey); the builder rejects a header-only initial setup, fabricated JSON participant list, missing final beacon or transcript mismatch.',
        'Names prove only embedded labels. Contributor identity, independent control and destruction of secret entropy require separate evidence and are not authenticated by this JSON or the builder.',
        'Hash the completed final transcript file and bind its repository-relative path and SHA256 in manifest.artifacts.ceremonyTranscript.']};
  }
  return {schema:'phase2-ceremony-manifest-templates/v1',activeMode:'asp',templatesOnly:true,finalParametersProduced:false,
    finalManifestSchema:'phase2-asp-production-circuits/v1',freezeSHA256:freeze.freezeSHA256,templates,transcriptTemplates};
}

export async function writeCeremonyFreeze(report,output,{rootDirectory=ROOT}={}){
  outputRelative(output);const root=await fs.realpath(rootDirectory),absolute=path.join(root,output),parent=path.dirname(absolute);
  await fs.mkdir(parent,{recursive:true});need(await fs.realpath(parent)===parent,'CEREMONY_OUTPUT_SYMLINK_REJECTED');
  const handle=await fs.open(absolute,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o644);
  try{await handle.writeFile(wire(report));await handle.sync();}finally{await handle.close();}return output;
}

export async function runCeremonyCLI(args=process.argv.slice(2)){
  let mode='asp',write=null,verify=null,commands=null,templates=null;
  for(let i=0;i<args.length;i++){
    const flag=args[i];need(['--mode','--write','--verify','--commands','--templates'].includes(flag)&&i+1<args.length,'CEREMONY_USAGE_INVALID');const value=args[++i];
    if(flag==='--mode')mode=value;else if(flag==='--write')write=value;else if(flag==='--verify')verify=value;else if(flag==='--commands')commands=value;else templates=value;
  }
  if(verify||commands||templates){need([verify,commands,templates].filter(Boolean).length===1&&!write,'CEREMONY_USAGE_INVALID');const input=verify??commands??templates;outputRelative(input);const freeze=await readJSON(await fs.realpath(ROOT),input);
    const checked=await verifyCeremonyFreeze(freeze);return verify?checked:commands?ceremonyCommands(freeze,{freezePath:input}):productionManifestTemplates(freeze,{freezePath:input});}
  const report=await inspectCeremonyPreparation({mode});if(write){await writeCeremonyFreeze(report,write);return {written:write,activeMode:mode,freezeSHA256:report.freezeSHA256,filesFrozen:report.inputs.installedDependencies.fileCount,
    commandsAvailable:report.commandsAvailable,setupExecuted:false,productionReady:false,blockers:report.blockers};}return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))runCeremonyCLI().then(result=>console.log(wire(result))).catch(error=>{
  console.error(JSON.stringify({error:error.code??error.name,setupExecuted:false,transactionsBroadcast:0}));process.exitCode=1;
});
