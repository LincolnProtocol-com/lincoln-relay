// SPDX-License-Identifier: Apache-2.0
// Public service bootstrap only: never imports deployment/client-prover scripts,
// reads a proving key, opens an account key, or creates a deployment journal.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { createPublicClient, http } from 'viem';
import { withPhase1ReadRetries } from '../phase1/rpc.mjs';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const sha = value => createHash('sha256').update(value).digest('hex');
export const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
export const stringify = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v, 2) + '\n';
export class Phase1RuntimeError extends Error {
  constructor(code) { super(code); this.name = 'Phase1RuntimeError'; this.code = code; }
}
export const ensure = (ok, code) => { if (!ok) throw new Phase1RuntimeError(code); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const blockHash = value => typeof value === 'string' && /^0x[a-f0-9]{64}$/i.test(value);
const address = value => typeof value === 'string' && /^0x[a-f0-9]{40}$/i.test(value) && !/^0x0{40}$/i.test(value);
const quantity = value => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value);
const TESTNET_HOSTS = new Set(['rpc.testnet.chain.robinhood.com', 'robinhood-sepolia-rpc.publicnode.com']);

function flag(env, name, fallback = false) {
  if (env[name] === undefined) return fallback;
  ensure(env[name] === '0' || env[name] === '1', 'INVALID_RUNTIME_FLAG'); return env[name] === '1';
}
function absolute(root, value) {
  ensure(typeof value === 'string' && value.trim() === value && value.length > 0 && !value.includes('\0'), 'INVALID_RUNTIME_PATH');
  return path.resolve(root, value);
}
async function regular(file, code) {
  let stat;
  try { stat = await fs.lstat(file); } catch { throw new Phase1RuntimeError(code); }
  ensure(stat.isFile() && !stat.isSymbolicLink(), code);
  // A bind-mounted secret may be visible to lstat but unreadable by the service
  // UID. Detect that before reserving fees or entering a broadcast boundary.
  // access checks permission only; key/password contents remain inside cast.
  try { await fs.access(file, constants.R_OK); } catch { throw new Phase1RuntimeError(code); }
  return stat;
}
async function jsonBytes(file, maximum = 32 * 1024 * 1024) {
  const stat = await regular(file, 'RUNTIME_FILE_UNAVAILABLE');
  ensure(stat.size > 0 && stat.size <= maximum, 'RUNTIME_FILE_SIZE');
  const bytes = await fs.readFile(file);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Phase1RuntimeError('INVALID_RUNTIME_JSON'); }
  ensure(object(value), 'INVALID_RUNTIME_JSON'); return { bytes, value };
}
export async function readJSON(file, root = ROOT) { return (await jsonBytes(absolute(root, file))).value; }

// The original pinned public profile is retained unchanged. Only the client
// transport uses an explicit override; pool/vault/index identities do not change.
export function serviceRpcUrl(value, { testnet, containerLocal = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new Phase1RuntimeError('INVALID_SERVICE_RPC'); }
  ensure(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/', 'INVALID_SERVICE_RPC');
  if (testnet) ensure(url.protocol === 'https:' && !url.port && TESTNET_HOSTS.has(url.hostname), 'TESTNET_RPC_NOT_ALLOWED');
  else {
    const loopback = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    const docker = containerLocal && url.href === 'http://anvil:8545/';
    ensure(loopback || docker, 'LOCAL_RPC_NOT_ALLOWED');
  }
  return url.href;
}
function artifactMetadata(artifacts, id) {
  const m = artifacts?._meta;
  ensure(m?.testOnly === true && m.productionReady === false && Array.isArray(m.allowedChainIds)
    && m.allowedChainIds.includes(id) && hash(m.sourceSetSHA256), 'NON_TEST_SERVICE_ARTIFACT');
}
function sourceRelative(root, value) {
  ensure(typeof value === 'string' && value.length > 0 && !path.isAbsolute(value)
    && !value.includes('\\') && !value.split('/').includes('..'), 'INVALID_PUBLIC_MANIFEST_PATH');
  return absolute(root, value);
}
async function publicCircuit({ root, artifacts, id, name, nPublic }) {
  const descriptor = name === 'transfer' ? artifacts._meta.circuit : null;
  const manifestPath = sourceRelative(root, descriptor?.manifest ?? `artifacts/phase1/circuits/${name}/manifest.json`);
  const { bytes, value: manifest } = await jsonBytes(manifestPath, 1024 * 1024);
  if (descriptor) ensure(hash(descriptor.manifestSHA256) && sha(bytes) === descriptor.manifestSHA256
    && descriptor.publicSignalCount === nPublic && descriptor.verifyFromR1cs === true, 'PUBLIC_MANIFEST_HASH_MISMATCH');
  ensure(manifest.schema === 'phase1-dev-circuits/v1' && manifest.testOnly === true && manifest.productionReady === false
    && manifest.officialFinalKey === false && manifest.allowedChainIds?.includes(id)
    && manifest.setup?.verifyFromR1cs === true && manifest.setup.officialCeremony === false
    && manifest.protocol === 'groth16' && manifest.curve === 'bn128'
    && manifest.counts?.publicInputs + manifest.counts?.outputs === nPublic, 'INVALID_TEST_CIRCUIT_MANIFEST');
  const verifierName = name === 'transfer' ? 'phase1/Phase1TransferVerifier.sol' : 'phase1/Phase1ExitVerifier.sol';
  ensure(hash(manifest.artifacts?.verifier?.sha256)
    && manifest.artifacts.verifier.sha256 === artifacts._meta.sourceDigests?.[verifierName], 'PUBLIC_VERIFIER_BUILD_MISMATCH');
  const info = manifest.artifacts?.vkey;
  ensure(hash(info?.sha256), 'INVALID_PUBLIC_VKEY_DESCRIPTOR');
  const vkeyPath = sourceRelative(root, info.path);
  const vkeyFile = await jsonBytes(vkeyPath, 128 * 1024), vkey = vkeyFile.value;
  ensure(sha(vkeyFile.bytes) === info.sha256 && vkey.protocol === 'groth16' && vkey.curve === 'bn128'
    && vkey.nPublic === nPublic && Array.isArray(vkey.IC) && vkey.IC.length === nPublic + 1, 'PUBLIC_VKEY_HASH_MISMATCH');
  // This is a public-file/build binding, not a repeat of the ceremony check.
  // On-chain verifier runtime pins are verified independently by the indexer.
  return { name, manifestPath, manifestSHA256: sha(bytes), vkeyPath, vkeySHA256: info.sha256 };
}
async function accountSpecs(env, root) {
  ensure(!(env.PHASE1_ACCOUNT_SPECS !== undefined && env.PHASE1_ACCOUNT_SPECS_PATH !== undefined), 'AMBIGUOUS_ACCOUNT_SPECS');
  if (env.PHASE1_ACCOUNT_SPECS_PATH !== undefined) return (await jsonBytes(absolute(root, env.PHASE1_ACCOUNT_SPECS_PATH), 65536)).value;
  if (env.PHASE1_ACCOUNT_SPECS === undefined) return {};
  let value;
  try { value = JSON.parse(env.PHASE1_ACCOUNT_SPECS); } catch { throw new Phase1RuntimeError('INVALID_ACCOUNT_SPECS'); }
  ensure(object(value), 'INVALID_ACCOUNT_SPECS'); return value;
}
async function accountsForService(original, specs, { root, enabled, container, testnet }) {
  ensure(object(original) && address(original.postman?.address) && address(original.relayer?.address), 'INVALID_SERVICE_ACCOUNTS');
  ensure(Object.keys(specs).every(role => ['postman', 'relayer'].includes(role)), 'NON_SERVICE_SIGNER_SPEC');
  for (const [role, spec] of Object.entries(specs)) ensure(object(spec)
    && Object.keys(spec).every(key => ['address', 'keystore', 'passwordFile'].includes(key))
    && (spec.address === undefined || same(spec.address, original[role]?.address)), 'SIGNER_SPEC_ADDRESS_MISMATCH');
  const accounts = {};
  for (const [role, originalAccount] of Object.entries(original)) {
    ensure(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(role) && object(originalAccount) && address(originalAccount.address), 'INVALID_SERVICE_ACCOUNTS');
    const value = { address: originalAccount.address };
    if (enabled && ['postman', 'relayer'].includes(role)) {
      const spec = { ...originalAccount, ...specs[role] };
      ensure((spec.keystore === undefined) === (spec.passwordFile === undefined), 'INCOMPLETE_SIGNER_SPEC');
      if (spec.keystore !== undefined) {
        value.keystore = absolute(root, spec.keystore); value.passwordFile = absolute(root, spec.passwordFile);
        await regular(value.keystore, 'SERVICE_KEYSTORE_UNAVAILABLE');
        await regular(value.passwordFile, 'SERVICE_PASSWORD_FILE_UNAVAILABLE');
      }
      ensure(!(container && testnet) || Boolean(value.keystore && value.passwordFile), 'CONTAINER_SIGNER_SPEC_REQUIRED');
    }
    // Keep all public roles, their case and insertion order: this is the existing
    // spending identity. A/B/owner signing descriptors are never returned.
    accounts[role] = value;
  }
  return accounts;
}

/** No filesystem writes. The injected client is for deterministic read-only tests. */
export async function loadServiceRuntime({ testnet = false, env = process.env, root = ROOT, client: injectedClient } = {}) {
  ensure(typeof testnet === 'boolean' && object(env), 'INVALID_RUNTIME_OPTIONS');
  root = absolute(ROOT, root);
  const tag = testnet ? 'testnet' : 'local', id = testnet ? 46630 : 31340;
  const container = flag(env, 'PHASE1_CONTAINER'), containerLocal = flag(env, 'PHASE1_CONTAINER_LOCAL');
  const signingEnabled = flag(env, 'PHASE1_SIGNING_ENABLED', !container);
  const files = {
    profile: env.PHASE1_PROFILE_PATH ?? `config/phase1-${tag}.json`,
    routes: env.PHASE1_ROUTES_PATH ?? `config/phase1-routes-${tag}.json`,
    config: env.PHASE1_CONFIG_PATH ?? `config/phase1-service-${tag}.json`,
    artifacts: env.PHASE1_ARTIFACTS_PATH ?? 'artifacts/phase1/contracts.json',
    routeArtifacts: env.PHASE1_ROUTE_ARTIFACTS_PATH ?? 'artifacts/phase1-routes/contracts.json',
  };
  const paths = Object.fromEntries(Object.entries(files).map(([key, file]) => [key, absolute(root, file)]));
  const [p, r, c, a, ra] = await Promise.all(Object.values(paths).map(file => jsonBytes(file)));
  const profile = p.value, routes = r.value, config = c.value, artifacts = a.value, routeArtifacts = ra.value;
  const profileSHA256 = sha(p.bytes), artifactSHA256 = sha(a.bytes);
  ensure(profile.schema === 'phase1-test-profile/v1' && profile.experimental === true && profile.testOnly === true
    && profile.productionReady === false && profile.chain?.id === id && blockHash(profile.genesisHash)
    && (testnet ? profile.localOnly === false && profile.testnetOnly === true : profile.localOnly === true), 'INVALID_SERVICE_PROFILE');
  // A profile never gets to weaken the original client-side loopback restriction.
  serviceRpcUrl(profile.chain.rpcUrl, { testnet });
  ensure(config.schema === 'phase1-service-config/v1' && config.testOnly === true && config.productionReady === false
    && config.chainId === id && same(config.genesisHash, profile.genesisHash)
    && config.baseProfileSHA256 === profileSHA256, 'SERVICE_CONFIG_MISMATCH');
  ensure(routes.schema === 'phase1-routes-profile/v1' && routes.testOnly === true && routes.productionReady === false
    && routes.chainId === id && same(routes.genesisHash, profile.genesisHash)
    && routes.baseProfileSHA256 === profileSHA256 && Array.isArray(routes.routes), 'SERVICE_ROUTE_BINDING_CHANGED');
  artifactMetadata(artifacts, id); artifactMetadata(routeArtifacts, id);
  ensure(profile.protocol?.artifactSHA256 === artifactSHA256 && profile.protocol?.sourceSetSHA256 === artifacts._meta.sourceSetSHA256,
    'SERVICE_CORE_ARTIFACT_CHANGED');
  ensure(routes.artifactSHA256 === sha(ra.bytes) && routeArtifacts._meta.originalPhase1ArtifactSHA256 === artifactSHA256
    && routeArtifacts._meta.schema === 'phase1-routes-contracts/v1', 'SERVICE_ROUTE_ARTIFACT_CHANGED');
  for (const name of ['Entrypoint', 'Phase1PrivacyPool', 'WithdrawalVerifier', 'CommitmentVerifier', 'Phase1TransferVerifier', 'Phase1ExitVerifier'])
    ensure(Array.isArray(artifacts[name]?.abi) && typeof artifacts[name]?.bytecode === 'string', 'MISSING_SERVICE_CONTRACT_ARTIFACT');
  ensure(Array.isArray(routeArtifacts.Phase1RouteAdapter?.abi) && typeof routeArtifacts.Phase1RouteAdapter?.bytecode === 'string', 'MISSING_SERVICE_ROUTE_ARTIFACT');
  paths.publicCircuits = await Promise.all([{ name: 'transfer', nPublic: 9 }, { name: 'holder-exit', nPublic: 5 }]
    .map(circuit => publicCircuit({ root, artifacts, id, ...circuit })));
  const rpcUrl = serviceRpcUrl(env.PHASE1_RPC_URL ?? profile.chain.rpcUrl, { testnet, containerLocal });
  const client = injectedClient ?? withPhase1ReadRetries(createPublicClient({ transport: http(rpcUrl, { timeout: 20000, retryCount: 0 }), cacheTime: 0 }));
  ensure(typeof client?.getChainId === 'function' && typeof client?.getBlock === 'function', 'INVALID_SERVICE_CLIENT');
  ensure(await client.getChainId() === id, 'SERVICE_CHAIN_MISMATCH');
  const genesisBlock = await client.getBlock({ blockNumber: 0n });
  ensure(genesisBlock?.number === 0n && blockHash(genesisBlock.hash) && same(genesisBlock.hash, profile.genesisHash), 'SERVICE_GENESIS_MISMATCH');
  if (!testnet) ensure(typeof client.request === 'function' && /anvil/i.test(await client.request({ method: 'web3_clientVersion' })), 'LOCAL_SERVICE_REQUIRES_ANVIL');
  const genesis = profile.genesisHash;
  config.accounts = await accountsForService(config.accounts, await accountSpecs(env, root), { root, enabled: signingEnabled, container, testnet });
  if (signingEnabled) {
    config.authTokenFile = absolute(root, env.PHASE1_AUTH_TOKEN_FILE ?? config.authTokenFile);
    await regular(config.authTokenFile, 'SERVICE_AUTH_TOKEN_UNAVAILABLE');
  } else delete config.authTokenFile;
  const directory = absolute(root, env.PHASE1_STATE_DIR ?? `artifacts/phase1-service/${tag}`);
  const budgetRoot = absolute(root, env.PHASE1_BUDGET_ROOT ?? root);
  const baselinePath = env.PHASE1_BUDGET_BASELINE_PATH === undefined ? null : absolute(root, env.PHASE1_BUDGET_BASELINE_PATH);
  ensure(!(container && testnet) || baselinePath, 'CONTAINER_BUDGET_BASELINE_REQUIRED');
  let budgetBaseline = null;
  if (baselinePath) {
    const baselineFile = await jsonBytes(baselinePath, 1024 * 1024);
    budgetBaseline = baselineFile.value;
    const spendingIdentity = sha(JSON.stringify({ chainId: id, genesis,
      accounts: Object.fromEntries(Object.entries(config.accounts).map(([role, value]) => [role, value.address])) }));
    ensure(testnet && budgetBaseline.schema === 'phase1-service-budget-baseline/v1' && budgetBaseline.testOnly === true
      && budgetBaseline.chainId === id && same(budgetBaseline.genesisHash, genesis)
      && budgetBaseline.artifactSHA256 === artifactSHA256 && budgetBaseline.spendingIdentity === spendingIdentity
      && quantity(budgetBaseline.externalFeeWei) && budgetBaseline.budgetWei === '2000000000000000'
      && BigInt(budgetBaseline.externalFeeWei) <= BigInt(budgetBaseline.budgetWei), 'INVALID_SERVICE_BUDGET_BASELINE');
    if (container && testnet) {
      // The initializer binds a fixed snapshot before the API can use this
      // volume. Re-running only `api` must not bypass that migration boundary.
      paths.volumeMarker = path.join(directory, '.phase1-volume.json');
      let marker;
      try { marker = (await jsonBytes(paths.volumeMarker, 1024 * 1024)).value; }
      catch { throw new Phase1RuntimeError('SERVICE_VOLUME_INITIALIZATION_REQUIRED'); }
      ensure(typeof budgetBaseline.generationId === 'string'
        && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(budgetBaseline.generationId)
        && ['read-only-fresh', 'migrated'].includes(budgetBaseline.ledgerMode)
        && marker.schema === 'phase1-volume-initialization/v1' && marker.generationId === budgetBaseline.generationId
        && marker.chainId === id && same(marker.genesisHash, genesis) && marker.ledgerMode === budgetBaseline.ledgerMode
        && marker.spendingIdentity === spendingIdentity && marker.baselineSHA256 === sha(baselineFile.bytes)
        && marker.profileSHA256 === profileSHA256 && marker.configSHA256 === sha(c.bytes)
        && object(budgetBaseline.seedSHA256) && isDeepStrictEqual(marker.seedSHA256, budgetBaseline.seedSHA256),
      'SERVICE_VOLUME_BINDING_MISMATCH');
    }
  }
  return { client, profile, config, routes, artifacts, routeArtifacts, tag, id, genesis, directory,
    budgetRoot, budgetBaseline, baselinePath, signingEnabled, rpcUrl, paths };
}
