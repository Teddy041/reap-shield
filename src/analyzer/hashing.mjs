/**
 * Streaming hashes (MD5, SHA-1, SHA-256) in a single pass, plus Shannon entropy.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

/** @returns {Promise<{md5:string, sha1:string, sha256:string, entropy:number, size:number}>} */
export function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const md5 = crypto.createHash('md5');
    const sha1 = crypto.createHash('sha1');
    const sha256 = crypto.createHash('sha256');
    const counts = new Float64Array(256);
    let size = 0;
    fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 })
      .on('data', (chunk) => {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        for (let i = 0; i < chunk.length; i += 1) counts[chunk[i]] += 1;
        size += chunk.length;
      })
      .on('error', reject)
      .on('end', () => {
        resolve({
          md5: md5.digest('hex'),
          sha1: sha1.digest('hex'),
          sha256: sha256.digest('hex'),
          entropy: entropyFromCounts(counts, size),
          size,
        });
      });
  });
}

export function entropyFromCounts(counts, total) {
  if (total === 0) return 0;
  let h = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / total;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1000) / 1000;
}

/** Shannon entropy (bits per byte, 0..8) of a buffer slice. */
export function entropy(buf) {
  const counts = new Float64Array(256);
  for (let i = 0; i < buf.length; i += 1) counts[buf[i]] += 1;
  return entropyFromCounts(counts, buf.length);
}
