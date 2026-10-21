// SPDX-License-Identifier: Apache-2.0
// Public document selection only. acceptedPolicies must come from canonical
// registry reads; state.mjs independently verifies the selection again.
const hash=value=>typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value);
const quantity=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(value);
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();

export function acceptedAssociationPolicy(asp,set,timestamp){
  if(!asp||!set||!quantity(String(timestamp))||!quantity(set.root)||!hash(set.digest)
    ||asp.providerRotated===true||asp.suspended===true)return null;
  const now=BigInt(timestamp),revoked=quantity(asp.revokedThroughEpoch??'0')?BigInt(asp.revokedThroughEpoch??'0'):null;
  if(revoked===null)return null;
  const policies=Array.isArray(asp.acceptedPolicies)?asp.acceptedPolicies:
    asp.expired===false&&asp.spendable!==false?[{...asp,acceptedUntil:asp.validUntil}]:[];
  for(const policy of policies){
    if(!quantity(policy.epoch)||!quantity(policy.root)||!quantity(policy.validUntil)||!quantity(policy.acceptedUntil)
      ||!hash(policy.cidDigest)||policy.root!==set.root||!same(policy.cidDigest,set.digest))continue;
    if(BigInt(policy.epoch)<=revoked||BigInt(policy.validUntil)<=now||BigInt(policy.acceptedUntil)<=now)continue;
    return {root:policy.root,epoch:policy.epoch,validUntil:policy.validUntil,
      acceptedUntil:policy.acceptedUntil,cidDigest:policy.cidDigest.toLowerCase()};
  }
  return null;
}
