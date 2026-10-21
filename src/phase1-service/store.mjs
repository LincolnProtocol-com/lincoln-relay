// SPDX-License-Identifier: Apache-2.0
// Trusted local service files, never an HTTP checkpoint import mechanism.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export class ServiceStoreError extends Error {
  constructor(code) { super(code); this.name = 'ServiceStoreError'; this.code = code; }
}
function check(ok, code) { if (!ok) throw new ServiceStoreError(code); }
async function readRegular(file) {
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    check(stat.isFile() && stat.size <= 128 * 1024 * 1024, 'INVALID_STORE_FILE');
    return await handle.readFile('utf8');
  } finally { await handle.close(); }
}

/** One lock per dedicated directory. Stale locks require explicit operator recovery. */
export async function openServiceStore({directory, identity, filename = 'checkpoints.json'} = {}) {
  check(typeof directory === 'string' && directory.length > 0 && typeof identity === 'string' && identity.length > 0, 'INVALID_STORE_OPTIONS');
  check(typeof filename === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(filename) && filename !== '.service.lock', 'INVALID_STORE_FILENAME');
  directory = path.resolve(directory);
  await fs.mkdir(directory, {recursive:true, mode:0o700});
  const stat = await fs.lstat(directory);
  check(stat.isDirectory() && !stat.isSymbolicLink(), 'INVALID_STORE_DIRECTORY');
  await fs.chmod(directory, 0o700);
  const lockPath = path.join(directory, '.service.lock'), target = path.join(directory, filename);
  const token = randomBytes(24).toString('hex');
  let lock;
  try { lock = await fs.open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') throw new ServiceStoreError('STORE_LOCKED'); throw error; }
  try { await lock.writeFile(JSON.stringify({schema:'phase1-service-lock/v1',pid:process.pid,token})); await lock.sync(); }
  catch (error) { await lock.close(); await fs.unlink(lockPath).catch(()=>{}); throw error; }
  let closing = false, closed = false, closePromise = null, tail = Promise.resolve();
  const available = () => check(!closing && !closed, 'STORE_CLOSED');
  const assertLock = async () => {
    let value; try { value = JSON.parse(await readRegular(lockPath)); } catch { throw new ServiceStoreError('STORE_LOCK_LOST'); }
    check(value.token === token && value.pid === process.pid, 'STORE_LOCK_LOST');
  };
  return {
    async read() {
      available(); await tail; await assertLock();
      let encoded;
      try { encoded = await readRegular(target); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
      let value; try { value = JSON.parse(encoded); } catch { throw new ServiceStoreError('STORE_CORRUPT'); }
      check(value && Object.keys(value).sort().join(',') === 'digest,identity,schema,value' && value.schema === 'phase1-service-store/v1', 'STORE_CORRUPT');
      check(value.identity === identity, 'STORE_IDENTITY_MISMATCH');
      const {digest:expected,...body} = value;
      check(typeof expected === 'string' && digest(body) === expected, 'STORE_CORRUPT');
      return structuredClone(value.value);
    },
    write(value) {
      available();
      // Serialize before enqueueing so later caller mutation cannot change a write.
      let encoded;
      try {
        check(value !== undefined, 'INVALID_STORE_VALUE');
        const body = {schema:'phase1-service-store/v1',identity,value:JSON.parse(JSON.stringify(value))};
        encoded = JSON.stringify({...body,digest:digest(body)}) + '\n';
      } catch (error) { if (error instanceof ServiceStoreError) throw error; throw new ServiceStoreError('INVALID_STORE_VALUE'); }
      check(Buffer.byteLength(encoded) <= 128 * 1024 * 1024, 'INVALID_STORE_VALUE');
      const run = tail.then(async () => {
        await assertLock();
        const temporary = path.join(directory, `.${filename}.${randomBytes(16).toString('hex')}.tmp`);
        let handle;
        try {
          handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          await handle.writeFile(encoded); await handle.sync(); await handle.close(); handle = null;
          await assertLock(); await fs.rename(temporary, target);
          const dir = await fs.open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
          try { await dir.sync(); } finally { await dir.close(); }
        } finally { if (handle) await handle.close(); await fs.unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;}); }
      });
      tail = run.catch(()=>{}); return run;
    },
    close() {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = (async () => {
        await tail;
        try { await assertLock(); await fs.unlink(lockPath); }
        finally { await lock.close(); closed = true; }
      })();
      return closePromise;
    },
  };
}
