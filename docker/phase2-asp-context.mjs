// Exact public-file build context audit; no Docker engine is required for this step.
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const ensure = (condition, code) => { if (!condition) throw new Error(code); };
export function contextFiles(source) {
  const rules = source.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  ensure(rules[0] === '**', 'CONTEXT_MUST_DENY_BY_DEFAULT');
  const files = [];
  for (let i = 1; i < rules.length; i++) {
    const rule = rules[i];
    if (rule.startsWith('!')) {
      const name = rule.slice(1);
      ensure(name && !name.includes('..') && !path.posix.isAbsolute(name) && !/[?*\[\]\\]/.test(name), 'CONTEXT_NEGATION_MUST_BE_EXACT');
      if (name.endsWith('/')) ensure([name + '*', name + '**'].includes(rules[i + 1]), 'CONTEXT_DIRECTORY_MUST_BE_RESTRICTED');
      else files.push(name);
    } else {
      // Restrict the exact directory immediately after reopening it. A single
      // star excludes only its children, preserving the directory traversal
      // needed by later exact file negations. Retain legacy /** audit support.
      const directory = rule.endsWith('/**') ? rule.slice(0, -2) : rule.endsWith('/*') ? rule.slice(0, -1) : null;
      ensure(directory !== null && rules[i - 1] === '!' + directory, 'UNSUPPORTED_CONTEXT_RULE');
    }
  }
  ensure(new Set(files).size === files.length, 'DUPLICATE_CONTEXT_FILE');
  for (const name of files) ensure(!/(?:^|\/)(?:\.git|\.phase1-private|node_modules|runtime|secrets?|wallets?|keystores?)(?:\/|$)|(?:\.zkey|\.wasm|\.r1cs|\.log|\.password|\.token)$|witness|\.env/i.test(name), 'PRIVATE_OR_GENERATED_CONTEXT_PATH');
  return files;
}
export async function auditContext({ root = ROOT } = {}) {
  const files = contextFiles(await fs.readFile(path.join(root, 'docker/phase2-asp.Dockerfile.dockerignore'), 'utf8'));
  const allowed = new Set(files), records = [];
  for (const file of files) {
    const absolute = path.join(root, file), stat = await fs.lstat(absolute);
    ensure(stat.isFile() && !stat.isSymbolicLink() && await fs.realpath(absolute) === absolute, 'CONTEXT_FILE_MUST_BE_REGULAR');
    const bytes = await fs.readFile(absolute);
    records.push({ file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
    if (file.endsWith('.mjs')) {
      const source = bytes.toString('utf8');
      const imports = [...source.matchAll(/\b(?:import|export)\s+(?:[^'";]+?\s+from\s+)?['"](\.[^'"]+)['"]/g),
        ...source.matchAll(/\bimport\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g)];
      for (const match of imports) {
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), match[1]));
        ensure(allowed.has(target), `MISSING_CONTEXT_IMPORT:${target}`);
      }
    }
  }
  return { schema: 'phase2-asp-docker-context/v1', ok: true, privateFilesIncluded: false,
    relativeImportsCovered: true, contextBytes: records.reduce((sum, entry) => sum + entry.bytes, 0),
    contextSHA256: createHash('sha256').update(JSON.stringify(records)).digest('hex'), files: records };
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  auditContext().then(report => console.log(JSON.stringify(report, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
