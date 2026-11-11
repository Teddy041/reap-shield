/**
 * Authenticode verification on Windows through Get-AuthenticodeSignature.
 * The target is passed through an environment variable, never interpolated
 * into the command line, and the file is only read, never executed.
 */
import { execFile, spawn } from 'node:child_process';
import path from 'node:path';

// Statements are separated with "; " but the hashtable body uses its own "; " separators,
// so the script is written as one line on purpose.
const SCRIPT =
  '$ErrorActionPreference = "Stop"; ' +
  '$s = Get-AuthenticodeSignature -LiteralPath $env:REAP_TARGET; ' +
  '$c = $s.SignerCertificate; ' +
  '[pscustomobject]@{ ' +
  'Status = [string]$s.Status; ' +
  'StatusMessage = [string]$s.StatusMessage; ' +
  'SignatureType = [string]$s.SignatureType; ' +
  'IsOSBinary = [bool]$s.IsOSBinary; ' +
  'Subject = $(if ($c) { $c.Subject } else { $null }); ' +
  'Issuer = $(if ($c) { $c.Issuer } else { $null }); ' +
  'NotAfter = $(if ($c) { $c.NotAfter.ToString("o") } else { $null }); ' +
  'Thumbprint = $(if ($c) { $c.Thumbprint } else { $null }); ' +
  'TimeStamped = [bool]$s.TimeStamperCertificate ' +
  '} | ConvertTo-Json -Compress';

const BATCH_SCRIPT =
  '$ErrorActionPreference = "Continue"; ' +
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ' +
  '$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json; ' +
  '$out = foreach ($p in $paths) { ' +
  'try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; $c = $s.SignerCertificate; ' +
  '[pscustomobject]@{ Path = $p; Status = [string]$s.Status; StatusMessage = [string]$s.StatusMessage; IsOSBinary = [bool]$s.IsOSBinary; ' +
  'Subject = $(if ($c) { $c.Subject } else { $null }); Issuer = $(if ($c) { $c.Issuer } else { $null }); ' +
  'NotAfter = $(if ($c) { $c.NotAfter.ToString("o") } else { $null }); Thumbprint = $(if ($c) { $c.Thumbprint } else { $null }); ' +
  'TimeStamped = [bool]$s.TimeStamperCertificate } } ' +
  'catch { [pscustomobject]@{ Path = $p; Status = "Error"; StatusMessage = $_.Exception.Message } } }; ' +
  'ConvertTo-Json -InputObject @($out) -Compress';

/**
 * Verify many files with a single PowerShell process (paths are sent on stdin
 * as JSON, never on the command line). Returns Map<path, result>.
 */
export async function verifyAuthenticodeMany(filePaths, chunkSize = 150) {
  const results = new Map();
  if (process.platform !== 'win32' || filePaths.length === 0) return results;
  for (let i = 0; i < filePaths.length; i += chunkSize) {
    const chunk = filePaths.slice(i, i + chunkSize).map((p) => path.resolve(p));
    const rows = await new Promise((resolve) => {
      const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', BATCH_SCRIPT], { windowsHide: true });
      let stdout = '';
      const timer = setTimeout(() => child.kill(), 30000 + chunk.length * 2000);
      // Decode as a stream so a signer name with non-ASCII characters split across chunks stays intact.
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (d) => (stdout += d));
      child.on('error', () => resolve([]));
      child.on('close', () => {
        clearTimeout(timer);
        try {
          resolve(JSON.parse(stdout.trim() || '[]'));
        } catch {
          resolve([]);
        }
      });
      // PowerShell decodes stdin with the OEM code page, which mangles paths such as
      // localized folder names (e.g. a Turkish "Desktop"). Escaping every non-ASCII character keeps stdin pure ASCII;
      // ConvertFrom-Json restores the original characters.
      child.stdin.end(JSON.stringify(chunk).replace(/[\u0080-￿]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`));
    });
    // One row per input path, in input order: map by position, not by the echoed path.
    const list = Array.isArray(rows) ? rows : [rows];
    if (list.length !== chunk.length) continue;
    for (const [idx, j] of list.entries()) {
      if (!j) continue;
      results.set(chunk[idx], {
        status: j.Status,
        statusMessage: j.StatusMessage,
        subject: j.Subject ?? null,
        issuer: j.Issuer ?? null,
        notAfter: j.NotAfter ?? null,
        thumbprint: j.Thumbprint ?? null,
        timestamped: Boolean(j.TimeStamped),
        isOsBinary: Boolean(j.IsOSBinary),
      });
    }
  }
  return results;
}

/**
 * @returns {Promise<null | {status:string, statusMessage:string, subject:string|null, issuer:string|null, notAfter:string|null, thumbprint:string|null, timestamped:boolean, isOsBinary:boolean}>}
 */
export function verifyAuthenticode(filePath) {
  if (process.platform !== 'win32') return Promise.resolve(null);
  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', SCRIPT],
      { env: { ...process.env, REAP_TARGET: path.resolve(filePath) }, windowsHide: true, timeout: 30000 },
      (err, stdout) => {
        if (err) return resolve(null);
        try {
          const j = JSON.parse(stdout.trim());
          resolve({
            status: j.Status,
            statusMessage: j.StatusMessage,
            subject: j.Subject,
            issuer: j.Issuer,
            notAfter: j.NotAfter,
            thumbprint: j.Thumbprint,
            timestamped: Boolean(j.TimeStamped),
            isOsBinary: Boolean(j.IsOSBinary),
          });
        } catch {
          resolve(null);
        }
      },
    );
  });
}
