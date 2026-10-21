#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Offline self-check: every shipped module loads, the image allowlist covers every
// import, and the deployed profile normalizes for each pool. No RPC, key or socket.
import fs from 'node:fs';
import {auditMainnetContext} from '../docker/mainnet/context.mjs';
import {normalizeProfile} from '../src/phase2-asp/sdk.mjs';
const modules=fs.readdirSync('src',{recursive:true}).filter(f=>f.endsWith('.mjs')).map(f=>`../src/${f}`);
for(const m of modules)await import(m);
const context=await auditMainnetContext();
const config=JSON.parse(fs.readFileSync('config/mainnet-deployed.json','utf8'));
for(const [id,profile] of Object.entries(config.profiles))normalizeProfile({...profile,relayer:profile.relayer??'0x0000000000000000000000000000000000000001'});
console.log(JSON.stringify({modules:modules.length,imageFiles:context.files.length,secretsIncluded:context.secretsIncluded,pools:Object.keys(config.profiles).length,ok:true}));
