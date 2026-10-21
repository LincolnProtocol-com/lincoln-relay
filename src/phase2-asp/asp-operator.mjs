// SPDX-License-Identifier: Apache-2.0
// Self-hosted availability policy, not original-source or sanctions screening.
// Signing and scheduling live in an explicitly enabled publisher adapter.
import { createHash } from 'node:crypto';
import path from 'node:path';
import { decodeEventLog, encodeFunctionData } from 'viem';
import { openServiceStore } from '../phase1-service/store.mjs';
import { syncPhase2State, phase2Identity } from './state.mjs';
import { associationSetDigest, buildAssociationSet, buildMerkleTree, normalizeProfile } from './sdk.mjs';
import {acceptedAssociationPolicy} from './association-policy.mjs';

const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { code }); };
const clone = value => structuredClone(value);
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hash = value => typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value);
const addr = value => { check(typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value), 'INVALID_OPERATOR_ADDRESS'); return value.toLowerCase(); };
const qty = value => { check(typeof value === 'bigint' || typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(value), 'INVALID_OPERATOR_QUANTITY'); return BigInt(value); };
const MAX_LIFETIME = 30 * 86400;
export const DEFAULT_ASP_OPERATOR_POLICY = Object.freeze({ lifetimeSeconds: 7 * 86400, renewalWindowSeconds: 86400, minPublishIntervalSeconds: 900, confirmations: 2, maxCommitments: 10000 });
/** Live journal bound. Older terminal jobs move to the append-only archive. */
export const ASP_OPERATOR_RETAINED_JOBS = 64;
export const ASP_OPERATOR_JOB_CAPACITY = 256;
const RECONCILE_CONCURRENCY = 8, POOL_SYNC_CONCURRENCY = 6;
const PENDING_STATES = ['prepared', 'broadcast-unknown', 'submitted'];
const anchorable = job => job.state === 'confirmed' && hash(job.confirmedBlockHash) && typeof job.confirmedBlock === 'string' && /^(0|[1-9][0-9]*)$/.test(job.confirmedBlock);
// Only jobs whose outcome can never change again leave the live journal. A
// superseded job without terminal sender evidence stays until it is released.
const archivable = job => anchorable(job) || job.state === 'reverted' || job.state === 'superseded' && !job.transactionHash && !!job.unsignedCancellation;
/** A prepared plan may lag the live union: notes that confirmed after its
 * snapshot simply join the next publication. The plan must still be a prefix of
 * the current union for every pool (pool commitments are append-only), carry the
 * same previous epoch, and be younger than the minimum publication interval,
 * so a fresh plan replaces it before the next publication would be due anyway.
 */
export function planCoversUnion(plan, planSet, current, chainNow, settings) {
  if (!planSet || !Array.isArray(planSet.pools) || !Array.isArray(planSet.leaves)) return false;
  if (qty(plan.preparedAt) + BigInt(settings.minPublishIntervalSeconds) < chainNow) return false;
  if (planSet.pools.length !== current.pools.length) return false;
  let planOffset = 0, currentOffset = 0;
  for (let i = 0; i < planSet.pools.length; i++) {
    const a = planSet.pools[i], b = current.pools[i];
    if (a.pool !== b.pool || a.scope !== b.scope || a.identity !== b.identity || a.commitmentCount > b.commitmentCount) return false;
    for (let j = 0; j < a.commitmentCount; j++) if (planSet.leaves[planOffset + j] !== current.leaves[currentOffset + j]) return false;
    planOffset += a.commitmentCount; currentOffset += b.commitmentCount;
  }
  return planOffset === planSet.leaves.length && currentOffset === current.leaves.length;
}
async function parallel(items, limit, fn) {
  const results = new Array(items.length); let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) { const index = cursor++; if (index >= items.length) return; results[index] = await fn(items[index], index); }
  }));
  return results;
}

function roster(profiles, requiredPools) {
  check(Array.isArray(profiles) && profiles.length > 0 && profiles.length <= 32, 'ASP_PROFILES_REQUIRED');
  const entries = profiles.map(profile => ({ profile, p: normalizeProfile(profile), identity: phase2Identity(profile) })).sort((a, b) => a.p.pool.localeCompare(b.p.pool));
  const pools = entries.map(e => e.p.pool), expected = requiredPools?.map(addr).sort();
  check(new Set(pools).size === pools.length, 'DUPLICATE_ASP_POOL');
  check(Array.isArray(expected) && expected.length === pools.length && new Set(expected).size === expected.length && expected.every((p, i) => p === pools[i]), 'ASP_POOL_ROSTER_MISMATCH');
  const first = entries[0];
  check(entries.every(e => e.p.chainId === first.p.chainId && e.p.registry === first.p.registry && e.p.provider === first.p.provider && e.profile.genesisHash === first.profile.genesisHash && e.profile.registry.runtimeCodeHash === first.profile.registry.runtimeCodeHash && String(e.profile.registry.startBlock) === String(first.profile.registry.startBlock)), 'SHARED_ASP_REGISTRY_MISMATCH');
  return entries;
}

/** All confirmed commitments remain members. Public nullifiers cannot identify their notes. */
export function buildOperatorAssociationSet({ profiles, requiredPools, states, maxCommitments = 10000 }) {
  const entries = roster(profiles, requiredPools);
  check(Array.isArray(states) && states.length === entries.length && new Set(states.map(s => s?.pool)).size === states.length, 'ASP_STATE_ROSTER_MISMATCH');
  const byPool = new Map(states.map(s => [s.pool, s])), leaves = [], pools = [];
  let first;
  for (const { profile, p, identity } of entries) {
    const state = byPool.get(p.pool);
    check(state?.schema === 'phase2-asp-public-state/v1' && state.identity === identity && state.chainId === p.chainId && state.scope === String(p.scope), 'ASP_VERIFIED_STATE_REQUIRED');
    check(hash(state.blockHash) && Array.isArray(state.commitments) && Array.isArray(state.policies), 'INVALID_ASP_OPERATOR_STATE');
    first ??= state;
    check(state.blockNumber === first.blockNumber && state.blockHash === first.blockHash && state.blockTimestamp === first.blockTimestamp && JSON.stringify(state.asp) === JSON.stringify(first.asp), 'ASP_SNAPSHOT_MISMATCH');
    const set = buildAssociationSet({ commitments: state.commitments, profile });
    leaves.push(...set.leaves);
    check(leaves.length <= maxCommitments && new Set(leaves).size === leaves.length, 'ASP_SET_CAPACITY_OR_DUPLICATE');
    pools.push({ pool: p.pool, scope: String(p.scope), identity, commitmentCount: state.commitments.length, poolRoot: state.root });
  }
  const root = String(buildMerkleTree(leaves).root), digest = associationSetDigest(leaves);
  const testOnly = entries[0].profile.testOnly === true;
  return { schema: 'phase2-asp-operator-association-set/v1', policy: 'all-current-notes', originScreening: false,
    chainId: entries[0].p.chainId, registry: entries[0].p.registry, provider: entries[0].p.provider,
    observedBlock: first.blockNumber, observedBlockHash: first.blockHash, observedTimestamp: first.blockTimestamp,
    pools, leaves, root, digest, testOnly, releaseCandidate: !testOnly, productionReady: false,
    limitations: ['Includes all indexed commitments, including spent notes; public nullifiers do not reveal note ownership.',
      'No deposit-origin, identity, sanctions or risk classification is performed.',
      'The configured pool roster and pinned RPC completeness are operator trust assumptions.'] };
}

/** Shares identical pinned-block reads across one roster snapshot. Only reads
 * whose answer is fixed by a block number or transaction hash are shared; any
 * 'latest'/tag read, and every method outside this list, keeps its own call.
 * Wrapper identities stay stable so pool-local safety probes keep their cache.
 */
function createSnapshotClient(client) {
  // Each pool sync clones its ABI, so an ABI is identified by content (hashed
  // once per object), never by object identity.
  const abiIds = new WeakMap(); let memo = new Map(), blockNumber = null;
  const abiId = abi => { if (!abi || typeof abi !== 'object') return String(abi); let id = abiIds.get(abi); if (id === undefined) { id = sha(abi); abiIds.set(abi, id); } return id; };
  const encode = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? `${v}n` : v);
  function shareKey(key, args) {
    const o = args[0];
    if (key === 'getChainId') return args.length === 0 ? key : null;
    if (args.length !== 1 || !o || typeof o !== 'object') return null;
    if (key === 'getTransactionReceipt') return hash(o.hash) && Object.keys(o).length === 1 ? `${key}:${o.hash.toLowerCase()}` : null;
    if (key === 'getLogs') return typeof o.fromBlock === 'bigint' && typeof o.toBlock === 'bigint' && o.blockHash === undefined ? `${key}:${encode(o)}` : null;
    if (typeof o.blockNumber !== 'bigint' || o.blockTag !== undefined) return null;
    if (key === 'readContract') return `${key}:${abiId(o.abi)}:${encode({ ...o, abi: undefined })}`;
    if (key === 'getBlock' || key === 'getCode' || key === 'getBalance') return `${key}:${encode(o)}`;
    return null;
  }
  const wrappers = new Map();
  const wrapper = key => {
    let fn = wrappers.get(key);
    if (!fn) {
      fn = (...args) => {
        const target = client[key], id = shareKey(key, args);
        if (id === null) return target.apply(client, args);
        let pending = memo.get(id);
        if (!pending) {
          pending = Promise.resolve(target.apply(client, args)); memo.set(id, pending);
          // A failed read is not shared: a pool's bounded same-height retry
          // must reach the RPC again rather than replay the first rejection.
          pending.catch(() => { if (memo.get(id) === pending) memo.delete(id); });
        }
        return pending;
      };
      wrappers.set(key, fn);
    }
    return fn;
  };
  const fixedBlockNumber = async () => { check(blockNumber !== null, 'ASP_SNAPSHOT_NOT_PINNED'); return blockNumber; };
  const atBlock = new Proxy(client, { get(target, key) {
    if (key === 'getBlockNumber') return fixedBlockNumber;
    return typeof Reflect.get(target, key, target) === 'function' ? wrapper(key) : Reflect.get(target, key, target);
  } });
  return { atBlock, pin(number) { blockNumber = number; memo = new Map(); }, release() { blockNumber = null; memo = new Map(); } };
}

/** Durable local journal. The caller must explicitly supply any send callback. */
export async function createASPOperator({ profiles, requiredPools, client, artifacts, directory, policy = {} }) {
  const entries = roster(profiles, requiredPools), p = entries[0].p;
  const settings = { ...DEFAULT_ASP_OPERATOR_POLICY, ...policy };
  check(Object.keys(settings).sort().join(',') === Object.keys(DEFAULT_ASP_OPERATOR_POLICY).sort().join(',') && Object.values(settings).every(Number.isSafeInteger), 'INVALID_ASP_OPERATOR_POLICY');
  check(settings.lifetimeSeconds > 0 && settings.lifetimeSeconds <= MAX_LIFETIME && settings.renewalWindowSeconds > 0 && settings.renewalWindowSeconds < settings.lifetimeSeconds && settings.minPublishIntervalSeconds > 0 && settings.minPublishIntervalSeconds < settings.lifetimeSeconds && settings.confirmations >= 0 && settings.confirmations <= 1024 && settings.maxCommitments > 0 && settings.maxCommitments <= 2 ** 20, 'INVALID_ASP_OPERATOR_POLICY');
  check(client && Array.isArray(artifacts?.Phase2ASPRegistry?.abi), 'ASP_CLIENT_AND_ARTIFACTS_REQUIRED');
  const registryABI = artifacts.Phase2ASPRegistry.abi;
  const identity = sha({ profiles: entries.map(e => e.identity), requiredPools: entries.map(e => e.p.pool), settings });
  const store = await openServiceStore({ directory, identity, filename: 'operator.json' });
  let saved, archiveStore;
  try {
    saved = await store.read() ?? { schema: 'phase2-asp-operator-journal/v1', checkpoints: {}, jobs: [], activeSet: null };
    check(saved.schema === 'phase2-asp-operator-journal/v1' && Array.isArray(saved.jobs), 'INVALID_ASP_OPERATOR_JOURNAL');
    // Plan ids stay unique across archiving: count every plan ever prepared,
    // not the jobs currently retained.
    saved.publicationCount ??= saved.jobs.length;
    check(Number.isSafeInteger(saved.publicationCount) && saved.publicationCount >= saved.jobs.length, 'INVALID_ASP_OPERATOR_JOURNAL');
    archiveStore = await openServiceStore({ directory: path.join(path.resolve(directory), 'archive'), identity, filename: 'operator-archive.json' });
  } catch (error) { await Promise.allSettled([archiveStore?.close(), store.close()]); throw error; }
  let tail = Promise.resolve();
  const serial = fn => { const run = tail.then(fn); tail = run.catch(() => {}); return run; };
  const persist = () => store.write(saved);
  const shared = createSnapshotClient(client);

  async function snapshot() {
    check(await client.getChainId() === p.chainId, 'CHAIN_ID_MISMATCH');
    const head = await client.getBlockNumber();
    check(head >= BigInt(settings.confirmations), 'ASP_CONFIRMATIONS_UNAVAILABLE');
    const blockNumber = head - BigInt(settings.confirmations), { atBlock } = shared;
    // Shared reads stay available to reconciliation in the same pass; the
    // caller releases them once its pass is complete.
    shared.pin(blockNumber);
    try {
      // Each pool bounds its own receipt reads; roster-wide reads at the common
      // pinned block are shared, so pools can sync concurrently in roster order.
      const states = await parallel(entries, POOL_SYNC_CONCURRENCY, ({ profile, p }) => syncPhase2State({ client: atBlock, profile, artifacts, checkpoint: saved.checkpoints[p.pool] }));
      const associationSet = buildOperatorAssociationSet({ profiles, requiredPools, states, maxCommitments: settings.maxCommitments });
      const chainNow = qty((await client.getBlock({ blockTag: 'latest' })).timestamp);
      check(chainNow >= qty(associationSet.observedTimestamp), 'ASP_CHAIN_TIME_MISMATCH');
      // A confirmation-delayed snapshot must not miss a newer registry publication.
      const [livePolicy, liveDigest, liveProvider] = await Promise.all(['latestPolicy', 'cidDigest', 'PROVIDER'].map(functionName => client.readContract({ address: p.registry, abi: registryABI, functionName, blockTag: 'latest' })));
      const currentPolicy = states[0].asp;
      check(String(livePolicy[0]) === currentPolicy.root && String(livePolicy[1]) === currentPolicy.epoch && String(livePolicy[2]) === currentPolicy.validUntil && liveDigest.toLowerCase() === currentPolicy.cidDigest && liveProvider.toLowerCase() === p.provider, 'ASP_REGISTRY_AHEAD_OF_SNAPSHOT');
      const latestEvent = states[0].policies.at(-1);
      const publishedAt = latestEvent ? qty((await atBlock.getBlock({ blockNumber: qty(latestEvent.blockNumber) })).timestamp) : null;
      // Pools share their pinned head read, so this roster-wide recheck must be
      // a fresh read: it is the one that detects a reorganization during the pass.
      check((await client.getBlock({ blockNumber })).hash === associationSet.observedBlockHash, 'SNAPSHOT_REORGANIZED');
      for (const state of states) saved.checkpoints[state.pool] = state.checkpoint;
      if (currentPolicy.root === associationSet.root && currentPolicy.cidDigest === associationSet.digest) saved.activeSet = associationSet;
      // Keep the last confirmed document while its epoch remains accepted on
      // chain. New policy metadata never authenticates old leaves as a new root.
      if(saved.activeSet&&!acceptedAssociationPolicy(currentPolicy,saved.activeSet,String(chainNow)))saved.activeSet=null;
      return { associationSet, currentPolicy, chainNow, publishedAt };
    } catch (error) { shared.release(); throw error; }
  }

  const newestConfirmed = () => saved.jobs.filter(anchorable).reduce((best, job) => best === null || qty(job.confirmedBlock) > qty(best.confirmedBlock) ? job : best, null);
  const canonical = async job => (await shared.atBlock.getBlock({ blockNumber: qty(job.confirmedBlock) })).hash === job.confirmedBlockHash;
  async function readPublication(job) {
    let receipt;
    try { receipt = await shared.atBlock.getTransactionReceipt({ hash: job.transactionHash }); }
    catch (error) { if (/TransactionReceiptNotFound|TransactionNotFound/.test(error.name ?? '')) return null; throw error; }
    return { receipt, block: await shared.atBlock.getBlock({ blockNumber: receipt.blockNumber }) };
  }
  function applyPublication(job, s, read) {
    if (read === null || read.block.hash !== read.receipt.blockHash) { job.state = 'submitted'; return false; }
    const { receipt } = read;
    if (receipt.status !== 'success') { job.state = 'reverted'; return false; }
    if (qty(s.associationSet.observedBlock) < receipt.blockNumber) { job.state = 'submitted'; return false; }
    const matching = receipt.logs.filter(log => addr(log.address) === p.registry).map(log => {
      try { return decodeEventLog({ abi: registryABI, topics: log.topics, data: log.data, strict: true }); } catch { return null; }
    }).filter(e => e?.eventName === 'PolicyUpdated' && String(e.args.epoch) === job.plan.expectedEpoch && String(e.args.root) === job.plan.associationRoot && e.args.cidDigest.toLowerCase() === job.plan.associationDigest && String(e.args.validUntil) === job.plan.validUntil);
    check(matching.length === 1 && receipt.transactionHash.toLowerCase() === job.transactionHash, 'ASP_PUBLICATION_RECEIPT_MISMATCH');
    job.state = 'confirmed'; job.confirmedBlock = String(receipt.blockNumber); job.confirmedBlockHash = receipt.blockHash;
    return true;
  }

  async function reconcile(s) {
    // Confirmed publications were verified against canonical receipts when they
    // were confirmed. One canonical read of the newest confirmed block covers
    // every older one: a canonical block hash commits to its whole ancestry.
    // If that anchor is no longer canonical, every confirmed job is rechecked.
    const anchor = newestConfirmed(), anchored = anchor !== null && await canonical(anchor);
    const selected = saved.jobs.filter(job => job.transactionHash && job.state !== 'reverted' && (job.state !== 'confirmed' || !anchored || !anchorable(job)));
    const reads = await parallel(selected, RECONCILE_CONCURRENCY, readPublication);
    let confirmedNow = false;
    selected.forEach((job, index) => { confirmedNow = applyPublication(job, s, reads[index]) || confirmedNow; });
    // A newly confirmed block must descend from the previous anchor. If the
    // chain moved underneath during this pass, keep the new ones pending; the
    // next pass rechecks the whole history before it anchors again.
    if (confirmedNow && anchored && !await canonical(anchor)) for (const job of selected) if (job.state === 'confirmed') job.state = 'submitted';
    // New notes can arrive after a publication. The complete current union
    // need not equal the published root; a confirmed job retains the exact
    // immutable set that was actually published.
    for (const job of saved.jobs) if (job.state === 'confirmed' && job.associationSet?.root === s.currentPolicy.root && job.associationSet?.digest === s.currentPolicy.cidDigest
      && acceptedAssociationPolicy(s.currentPolicy, job.associationSet, String(s.chainNow))) saved.activeSet = job.associationSet;
    const pending = saved.jobs.find(j => PENDING_STATES.includes(j.state));
    // A never-broadcast plan is replaced once the registry moved on, its expiry
    // passed, it no longer prefixes the live union, or it aged past the minimum
    // publication interval. Newer notes alone do not supersede it: under steady
    // activity a plan that had to match the very latest union could never be sent.
    // Unknown or submitted broadcasts must remain locked until reconciled.
    if (pending?.state === 'prepared' && (qty(s.currentPolicy.epoch) >= qty(pending.plan.expectedEpoch)
      || qty(pending.plan.validUntil) <= s.chainNow
      || !planCoversUnion(pending.plan, pending.associationSet, s.associationSet, s.chainNow, settings))) pending.state = 'superseded';
  }

  /** Moves the oldest finished jobs out of the live journal. The newest
   * confirmed job always stays: it anchors reconciliation and carries the
   * active document. Archive first, then drop; a crash in between only
   * leaves a duplicate the next archive pass skips by id.
   */
  async function archive(s) {
    if (saved.jobs.length <= ASP_OPERATOR_RETAINED_JOBS) return;
    const anchor = newestConfirmed(), moved = [];
    for (const job of saved.jobs) {
      if (saved.jobs.length - moved.length <= ASP_OPERATOR_RETAINED_JOBS) break;
      if (job !== anchor && archivable(job)) moved.push(job);
    }
    if (!moved.length) return;
    const archived = await archiveStore.read() ?? { schema: 'phase2-asp-operator-archive/v1', jobs: [] };
    check(archived.schema === 'phase2-asp-operator-archive/v1' && Array.isArray(archived.jobs), 'INVALID_ASP_OPERATOR_ARCHIVE');
    const known = new Set(archived.jobs.map(job => job.id));
    // The immutable set itself is already archived by digest in the publication
    // directory; the journal archive keeps the plan, hashes and outcome only.
    for (const { associationSet, ...job } of moved) if (!known.has(job.id)) archived.jobs.push({ ...job, archivedAtBlock: s.associationSet.observedBlock });
    await archiveStore.write(archived);
    const ids = new Set(moved.map(job => job.id));
    saved.jobs = saved.jobs.filter(job => !ids.has(job.id));
  }

  function response(s, decision, reason, plan = null) {
    return clone({ schema: 'phase2-asp-operator-result/v1', policy: 'all-current-notes', originScreening: false, unsignedOnly: true,
      productionReady: false, testOnly: entries[0].profile.testOnly === true, releaseCandidate: entries[0].profile.testOnly === false, decision, reason, associationSet: s.associationSet,
      currentPolicy: { ...s.currentPolicy, expired: qty(s.currentPolicy.validUntil) <= s.chainNow },
      activePolicy:saved.activeSet?acceptedAssociationPolicy(s.currentPolicy,saved.activeSet,String(s.chainNow)):null,
      chainTimestamp: String(s.chainNow), lastPublicationTimestamp: s.publishedAt === null ? null : String(s.publishedAt), activeAssociationSet: saved.activeSet, plan,
      publicationCount: saved.publicationCount, jobs: saved.jobs.map(({ associationSet, ...job }) => job) });
  }

  async function run(prepare) {
    try { return await pass(prepare); } finally { shared.release(); }
  }
  async function pass(prepare) {
    const s = await snapshot(); await reconcile(s); await archive(s);
    const pending = saved.jobs.find(j => PENDING_STATES.includes(j.state));
    let result;
    if (pending) result = response(s, 'pending', pending.state === 'prepared' ? 'Existing unsigned plan; no duplicate epoch publication.' : 'Resolve the known hash or unknown broadcast before publishing again.', pending.plan);
    else {
      const same = s.currentPolicy.root === s.associationSet.root && s.currentPolicy.cidDigest === s.associationSet.digest;
      const renewalDue = qty(s.currentPolicy.validUntil) <= s.chainNow + BigInt(settings.renewalWindowSeconds);
      const intervalDue = s.publishedAt === null || s.chainNow >= s.publishedAt + BigInt(settings.minPublishIntervalSeconds);
      if (same && !renewalDue) result = response(s, 'unchanged', 'Identical root and digest; expiry is outside the renewal window.');
      else if (!intervalDue) result = response(s, 'deferred', 'Minimum publication interval protects pending normal proofs from repeated epoch changes.');
      else if (!prepare) result = response(s, same ? 'renew' : 'publish', 'A publication is due; status does not create a job.');
      else {
        check(qty(s.currentPolicy.epoch) + 1n < 1n << 64n, 'ASP_EPOCH_EXHAUSTED');
        const validUntil = String(s.chainNow + BigInt(settings.lifetimeSeconds));
        const transaction = { chainId: p.chainId, from: p.provider, to: p.registry, value: '0', data: encodeFunctionData({ abi: registryABI, functionName: 'updateRoot', args: [BigInt(s.associationSet.root), s.associationSet.digest, BigInt(validUntil)] }) };
        const body = { schema: 'phase2-asp-operator-plan/v1', chainId: p.chainId, registry: p.registry, provider: p.provider,
          expectedEpoch: String(qty(s.currentPolicy.epoch) + 1n), previousPolicy: { root: s.currentPolicy.root, epoch: s.currentPolicy.epoch, validUntil: s.currentPolicy.validUntil, cidDigest: s.currentPolicy.cidDigest },
          associationRoot: s.associationSet.root, associationDigest: s.associationSet.digest, observedBlock: s.associationSet.observedBlock,
          observedBlockHash: s.associationSet.observedBlockHash, preparedAt: String(s.chainNow), validUntil, transaction, unsignedOnly: true,
          publicationAttempt: saved.publicationCount };
        const plan = { ...body, id: sha(body) };
        check(saved.jobs.length < ASP_OPERATOR_JOB_CAPACITY, 'ASP_JOB_CAPACITY_REACHED');
        saved.jobs.push({ id: plan.id, state: 'prepared', plan, associationSet: s.associationSet, transactionHash: null }); saved.publicationCount++;
        result = response(s, same ? 'renew' : 'publish', same ? 'Only extend the identical association set near expiry.' : 'Publish the complete union of configured pools, never a delta.', plan);
      }
    }
    await persist(); return result;
  }

  async function recordHash(id, transactionHash) {
    check(hash(transactionHash), 'INVALID_ASP_TRANSACTION_HASH');
    const job = saved.jobs.find(j => j.id === id);
    check(job && PENDING_STATES.includes(job.state), 'ASP_JOB_NOT_RECORDABLE');
    check(!job.transactionHash || job.transactionHash === transactionHash.toLowerCase(), 'ASP_DIFFERENT_HASH_ALREADY_RECORDED');
    const tx = await client.getTransaction({ hash: transactionHash });
    const expected = job.plan.transaction;
    check(tx.hash?.toLowerCase() === transactionHash.toLowerCase() && addr(tx.from) === expected.from && addr(tx.to) === expected.to && (tx.input ?? tx.data)?.toLowerCase() === expected.data.toLowerCase() && qty(tx.value) === 0n && (tx.chainId === undefined || Number(tx.chainId) === p.chainId) && await client.getChainId() === p.chainId, 'ASP_SOURCE_TRANSACTION_MISMATCH');
    job.transactionHash = transactionHash.toLowerCase(); job.state = 'submitted'; await persist(); return clone(job);
  }

  return {
    prepare: () => serial(() => run(true)), status: () => serial(() => run(false)),
    recordHash: (id, transactionHash) => serial(() => recordHash(id, transactionHash)),
    // Internal sender recovery only. A terminal sender record must prove that
    // its exact reservation was cancelled before any signature or broadcast.
    cancelUnsigned: (id, evidence) => serial(async () => {
      const job = saved.jobs.find(j => j.id === id), expected = job?.plan.transaction;
      check(job && ['prepared', 'broadcast-unknown', 'superseded'].includes(job.state) && !job.transactionHash, 'ASP_JOB_NOT_UNSIGNED');
      check(evidence?.unsigned === true && ['cancelled', 'not-submitted'].includes(evidence.status)
        && evidence.id === `asp-${id}` && evidence.chainId === expected.chainId
        && addr(evidence.from) === expected.from && addr(evidence.to) === expected.to
        && evidence.data?.toLowerCase() === expected.data.toLowerCase() && evidence.value === '0'
        && !Object.hasOwn(evidence, 'hash') && !Object.hasOwn(evidence, 'transactionHash')
        && !Object.hasOwn(evidence, 'rawTransaction'), 'ASP_UNSIGNED_CANCELLATION_EVIDENCE_INVALID');
      job.state = 'superseded'; job.unsignedCancellation = clone(evidence); await persist(); return clone(job);
    }),
    /** Resolves to the recorded job plus `result`, the operator result for the
     * same snapshot after the hash was recorded, so a scheduler need not take
     * another snapshot merely to publish this tick's outcome.
     */
    sendPrepared: (id, send) => serial(async () => {
      check(typeof send === 'function', 'EXPLICIT_ASP_SEND_CALLBACK_REQUIRED');
      let s;
      try { s = await snapshot(); await reconcile(s); } finally { shared.release(); }
      const job = saved.jobs.find(j => j.id === id);
      check(job?.state === 'prepared', 'ASP_JOB_NOT_SENDABLE');
      check(job.plan.associationRoot === job.associationSet?.root && job.plan.associationDigest === job.associationSet?.digest
        && planCoversUnion(job.plan, job.associationSet, s.associationSet, s.chainNow, settings)
        && job.plan.previousPolicy.epoch === s.currentPolicy.epoch && qty(job.plan.validUntil) > s.chainNow && qty(job.plan.validUntil) <= s.chainNow + BigInt(MAX_LIFETIME), 'ASP_PLAN_STALE');
      // Persist before handing control to a sender. An exception is an unknown broadcast,
      // never authorization to call send again. recordHash restores an already sent call.
      job.state = 'broadcast-unknown'; await persist();
      const result = await send(clone(job.plan.transaction));
      const sent = await recordHash(id, typeof result === 'string' ? result : result?.hash);
      return { ...sent, result: response({ ...s, associationSet: job.associationSet }, 'pending', 'Resolve the known hash or unknown broadcast before publishing again.', sent.plan) };
    }),
    async close() { await tail; await Promise.allSettled([archiveStore.close(), store.close()]); }
  };
}
