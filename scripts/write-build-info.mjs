/**
 * Records build metadata that the packaged app needs at runtime:
 * the absolute path of the sibling REA checkout (if present and built).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const reaHome = process.env.REA_HOME ? path.resolve(process.env.REA_HOME) : path.resolve(root, '..', '..', 'rea');
const reaBuilt = fs.existsSync(path.join(reaHome, 'scripts', 'rea.mjs')) && fs.existsSync(path.join(reaHome, 'dist'));
const info = { builtAt: new Date().toISOString(), reaHome: reaBuilt ? reaHome : null };
fs.writeFileSync(path.join(root, 'src', 'main', 'build-info.json'), `${JSON.stringify(info, null, 2)}\n`);
console.log(`build-info.json: REA ${reaBuilt ? reaHome : 'not found (built app will look on PATH)'}`);
