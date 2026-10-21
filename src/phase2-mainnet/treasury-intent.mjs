// SPDX-License-Identifier: Apache-2.0
// Fixed mainnet treasury transfer shape. No RPC, keys or signing here.
import {encodeFunctionData,parseAbi} from 'viem';

/** The only destination a treasury transfer can ever have. Not configurable. */
export const TREASURY_SAFE='0x9cf17a6e3c75d200f58283a165c442a8a3994555';
/** The only signer that may send a treasury transfer (the relay processor). */
export const TREASURY_RELAY='0x8d890058818edbc222e6e01f501dc77fbff6f4dc';
export const TREASURY_NATIVE='0x'+'0'.repeat(40);
export const TREASURY_KIND='safe-treasury-v2';
/** A plain ETH send uses 21000 gas; an ERC20 transfer well under 100000. */
export const TREASURY_MAX_GAS=100000n;
/** ETH the relay keeps beyond the signer reserve so relaying never stalls. */
export const TREASURY_WORKING_CAPITAL_WEI=20000000000000000n;
export const TREASURY_POLICY=Object.freeze({intervalSeconds:3600,nativeThresholdWei:'100000000000000',tokenThresholdGasQuotes:10,
  workingCapitalWei:String(TREASURY_WORKING_CAPITAL_WEI),maxGas:String(TREASURY_MAX_GAS)});
export const TREASURY_TRANSFER_ABI=parseAbi(['function transfer(address to,uint256 value) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)']);
const ID=/^treasury:([a-f0-9]{40}):([1-9][0-9]{0,8})$/;
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();

/** The exact transaction for one transfer of `amount` units of `asset` to the Safe. */
export function treasuryTransfer({asset,amount}={}){
  need(typeof asset==='string'&&/^0x[0-9a-fA-F]{40}$/.test(asset),'MAINNET_TREASURY_ASSET_INVALID');asset=asset.toLowerCase();
  need(typeof amount==='string'&&/^[1-9][0-9]{0,38}$/.test(amount)&&BigInt(amount)<(1n<<128n),'MAINNET_TREASURY_AMOUNT_INVALID');
  const native=asset===TREASURY_NATIVE;
  return {kind:TREASURY_KIND,treasuryAsset:asset,treasuryAmount:amount,to:native?TREASURY_SAFE:asset,
    data:native?'0x':encodeFunctionData({abi:TREASURY_TRANSFER_ABI,functionName:'transfer',args:[TREASURY_SAFE,BigInt(amount)]}).toLowerCase(),
    value:native?amount:'0'};
}
/** Deterministic, sequence-numbered reservation ID: a crash can only resume the same ID. */
export function treasuryId(asset,sequence){
  need(Number.isSafeInteger(sequence)&&sequence>0&&sequence<1e9,'MAINNET_TREASURY_SEQUENCE_INVALID');
  return `treasury:${asset.toLowerCase().slice(2)}:${sequence}`;
}
/** Every signer instance (relay API included) validates a treasury entry with
 * this. Only the relay address may hold one, and only to the fixed Safe. */
export function assertTreasuryEntry(entry,{address}={}){
  need(same(address,TREASURY_RELAY)&&entry?.kind===TREASURY_KIND,'MAINNET_TREASURY_SIGNER_FORBIDDEN');
  const match=ID.exec(entry.id??'');need(match&&match[1]===String(entry.treasuryAsset).slice(2),'MAINNET_TREASURY_ID_INVALID');
  const expected=treasuryTransfer({asset:entry.treasuryAsset,amount:entry.treasuryAmount});
  need(same(entry.to,expected.to)&&entry.data===expected.data&&entry.value===expected.value,'MAINNET_TREASURY_TARGET_OR_VALUE_FORBIDDEN');
  if(entry.gas!==undefined)need(/^[1-9][0-9]*$/.test(entry.gas)&&BigInt(entry.gas)<=TREASURY_MAX_GAS,'MAINNET_TREASURY_GAS_LIMIT');
  return expected;
}
