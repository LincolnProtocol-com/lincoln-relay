#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Write a copy of the public deployed profile with every pool's `relayer` set to
// your relay address. Property order is preserved; nothing else changes.
//
//   node scripts/set-relayer.mjs <relay address> <output mainnet-deployed.json> [input]
import fs from 'node:fs';
import {getAddress,isAddress} from 'viem';
const [address,output,input='config/mainnet-deployed.json']=process.argv.slice(2);
if(!address||!output||!isAddress(address)){console.error('usage: set-relayer.mjs <relay address> <output path> [input]');process.exit(2);}
if(fs.existsSync(output)){console.error(`refusing to overwrite ${output}`);process.exit(1);}
const config=JSON.parse(fs.readFileSync(input,'utf8'));
for(const profile of Object.values(config.profiles))profile.relayer=getAddress(address);
for(const routes of Object.values(config.routesByPool??{}))for(const route of routes)if(route.targetProfile&&'relayer' in route.targetProfile)route.targetProfile.relayer=getAddress(address);
fs.writeFileSync(output,JSON.stringify(config,null,2)+'\n',{mode:0o644,flag:'wx'});
console.log(`wrote ${output}: relayer ${getAddress(address)} on ${Object.keys(config.profiles).length} pools`);
