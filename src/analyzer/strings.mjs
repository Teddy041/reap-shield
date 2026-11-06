/**
 * ASCII / UTF-16LE string extraction and indicator-of-compromise (IOC) rules.
 */
import fs from 'node:fs/promises';
import { LIMITS } from './config.mjs';

/** Read at most `max` bytes of a file. */
export async function readCapped(filePath, max) {
  const fh = await fs.open(filePath, 'r');
  try {
    const { size } = await fh.stat();
    const len = Math.min(size, max);
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, 0);
    return { buf, truncated: size > max };
  } finally {
    await fh.close();
  }
}

/**
 * Extract printable ASCII and UTF-16LE strings.
 * @returns {{ascii: string[], unicode: string[], total: number}}
 */
export function extractStrings(buf, minLen = 5) {
  const latin = buf.toString('latin1');
  const ascii = [];
  const unicode = [];
  const asciiRe = new RegExp(`[\\x20-\\x7e]{${minLen},}`, 'g');
  const uniRe = new RegExp(`(?:[\\x20-\\x7e]\\x00){${minLen},}`, 'g');
  let m;
  while ((m = asciiRe.exec(latin)) !== null && ascii.length < LIMITS.maxStringsPerFile) ascii.push(m[0]);
  while ((m = uniRe.exec(latin)) !== null && unicode.length < LIMITS.maxStringsPerFile) unicode.push(m[0].replace(/\x00/g, ''));
  return { ascii, unicode, total: ascii.length + unicode.length };
}

// ---------------------------------------------------------------- IOC rules

const BENIGN_HOST = /(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|digicert\.com|verisign\.com|symantec\.com|symcb\.com|symcd\.com|thawte\.com|geotrust\.com|globalsign\.(com|net)|sectigo\.com|comodoca\.com|usertrust\.com|entrust\.net|godaddy\.com|letsencrypt\.org|w3\.org|xmlsoap\.org|openssl\.org|apache\.org|mozilla\.org|electronjs\.org|nodejs\.org|npmjs\.(com|org)|github\.com\/electron|chromium\.org|google\.com\/chrome|example\.(com|org|net)|localhost|schemas\.(microsoft|openxmlformats)\.(com|org)|ns\.adobe\.com|purl\.org|python\.org|ietf\.org|unicode\.org|creativecommons\.org|gnu\.org|opensource\.org|json-schema\.org|reactjs\.org|react\.dev|fb\.me|sentry\.io|crashpad|gstatic\.com|googleapis\.com\/css)$/i;

const PAYLOAD_HOSTS = /(pastebin\.com|paste\.ee|hastebin\.com|ghostbin|rentry\.co|controlc\.com|transfer\.sh|anonfiles\.com|file\.io|gofile\.io|catbox\.moe|filebin\.net|temp\.sh|bashupload\.com|ngrok\.io|ngrok-free\.app|trycloudflare\.com|duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|serveo\.net|portmap\.io|playit\.gg|raw\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|iplogger\.(org|com)|grabify\.link|ip-api\.com|ipinfo\.io|api\.ipify\.org|checkip\.amazonaws\.com|icanhazip\.com)/i;

/**
 * @typedef {object} IocRule
 * @property {string} id
 * @property {RegExp} re   Global regex.
 * @property {string} category
 * @property {'info'|'low'|'medium'|'high'|'critical'} severity
 * @property {string} title
 * @property {string} description
 * @property {(m: string) => boolean} [keep]  Extra filter.
 * @property {(m: string) => string} [redact] Masking for secrets in reports.
 */

const maskTail = (s) => (s.length > 24 ? `${s.slice(0, Math.max(12, s.length - 28))}…[redacted]` : s);

/** @type {IocRule[]} */
export const IOC_RULES = [
  {
    id: 'ioc.discord-webhook', category: 'network', severity: 'critical',
    title: 'Discord webhook URL',
    description: 'Discord webhooks are the most common exfiltration channel for token and password stealers.',
    re: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d{15,22}\/[\w-]{40,90}/gi,
    redact: maskTail,
  },
  {
    id: 'ioc.telegram-bot', category: 'network', severity: 'critical',
    title: 'Telegram Bot API token',
    description: 'Hard-coded Telegram bot tokens are used to exfiltrate stolen data to a chat.',
    re: /(?:api\.telegram\.org\/bot)?\b\d{8,11}:AA[\w-]{32,34}\b/g,
    redact: maskTail,
  },
  {
    id: 'ioc.discord-token', category: 'credentials', severity: 'high',
    title: 'Embedded Discord user/bot token',
    description: 'A string matching the Discord token format is embedded in the file.',
    re: /\b[MNO][A-Za-z\d_-]{23,27}\.[\w-]{6}\.[\w-]{27,40}\b/g,
    redact: maskTail,
  },
  {
    id: 'ioc.onion', category: 'network', severity: 'high',
    title: 'Tor hidden service address',
    description: '.onion addresses are typical for ransomware portals and anonymised C2.',
    re: /\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b/gi,
  },
  {
    id: 'ioc.miner', category: 'network', severity: 'high',
    title: 'Cryptocurrency miner pool / tooling',
    description: 'Mining pool protocols or miner names indicate a cryptojacker.',
    re: /\b(?:stratum\+(?:tcp|ssl|tls):\/\/[^\s"']+|xmrig|cpuminer|nicehash|minexmr|supportxmr|nanopool\.org|2miners\.com|moneroocean)\b/gi,
  },
  {
    id: 'ioc.payload-host', category: 'network', severity: 'medium',
    title: 'Paste site, file drop, tunnel or IP-lookup service',
    description: 'Commonly used to host second-stage payloads, expose C2 through tunnels or geolocate victims.',
    re: /https?:\/\/[^\s"'<>`\\]{3,300}/gi,
    keep: (m) => PAYLOAD_HOSTS.test(m),
  },
  {
    id: 'ioc.ip-port', category: 'network', severity: 'medium',
    title: 'Hard-coded public IP address with port',
    description: 'Raw IP:port pairs are typical C2 endpoints that avoid DNS.',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):\d{2,5}\b/g,
    keep: (m) => isPublicIPv4(m.split(':')[0]),
  },
  {
    id: 'ioc.ip-url', category: 'network', severity: 'medium',
    title: 'URL pointing to a raw IP address',
    description: 'URLs that use an IP instead of a domain name are a common C2 / download pattern.',
    re: /https?:\/\/(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?:\/[^\s"'<>]*)?/gi,
    keep: (m) => isPublicIPv4(m.replace(/^https?:\/\//i, '').split(/[:/]/)[0]),
  },
  {
    id: 'ioc.ipv4', category: 'network', severity: 'low',
    title: 'Hard-coded public IPv4 address',
    description: 'Public IP addresses embedded in the file. Many are benign (DNS resolvers, version strings).',
    re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g,
    keep: (m) => isPublicIPv4(m) && !/^(?:\d\.){3}\d$/.test(m), // skip "1.2.3.4"-style version numbers
  },
  {
    id: 'ioc.url', category: 'network', severity: 'info',
    title: 'Embedded URLs',
    description: 'URLs referenced by the file (well-known vendor / certificate URLs are filtered out).',
    re: /\b(?:https?|ftp|wss?):\/\/[^\s"'<>`\\(){}|^]{4,300}/gi,
    keep: (m) => {
      const host = m.replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0];
      return !BENIGN_HOST.test(host) && !PAYLOAD_HOSTS.test(m);
    },
  },
  // ---- Execution / LOLBins
  {
    id: 'ioc.ps-encoded', category: 'execution', severity: 'high',
    title: 'Encoded PowerShell command',
    description: 'Base64-encoded PowerShell is used to hide commands from inspection.',
    re: /powershell(?:\.exe)?[^\n]{0,120}?\s-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{24,}/gi,
  },
  {
    id: 'ioc.ps-cradle', category: 'execution', severity: 'high',
    title: 'PowerShell download cradle / in-memory execution',
    description: 'Downloads and runs code without touching disk.',
    re: /\b(?:IEX\s*\(|Invoke-Expression|DownloadString\s*\(|DownloadData\s*\(|Net\.WebClient|Invoke-WebRequest|iwr\s+-u|Start-BitsTransfer|\[System\.Reflection\.Assembly\]::Load|FromBase64String\s*\()/gi,
  },
  {
    id: 'ioc.lolbin', category: 'execution', severity: 'medium',
    title: 'Living-off-the-land binary abuse',
    description: 'Signed Windows tools frequently abused to download or run payloads.',
    re: /\b(?:certutil(?:\.exe)?\s+[^\n]{0,40}-(?:urlcache|decode)|mshta(?:\.exe)?\s+(?:https?|vbscript|javascript)|regsvr32(?:\.exe)?\s+[^\n]{0,40}\/i:https?|rundll32(?:\.exe)?\s+[^\n]{0,60}javascript:|bitsadmin(?:\.exe)?\s+\/transfer|wmic\s+process\s+call\s+create|cmstp(?:\.exe)?\s+\/s)/gi,
  },
  {
    id: 'ioc.defender-tamper', category: 'evasion', severity: 'high',
    title: 'Security product tampering',
    description: 'Attempts to disable Microsoft Defender or add exclusions.',
    re: /\b(?:Set-MpPreference\s+-Disable\w+|Add-MpPreference\s+-Exclusion\w+|DisableAntiSpyware|DisableRealtimeMonitoring|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)\b/gi,
  },
  {
    id: 'ioc.ransom', category: 'fileops', severity: 'critical',
    title: 'Backup / shadow copy destruction',
    description: 'Commands that delete recovery data are a hallmark of ransomware.',
    re: /\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit(?:\.exe)?\s+\/set\s+\{default\}\s+(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup))/gi,
  },
  {
    id: 'ioc.ransom-note', category: 'fileops', severity: 'medium',
    title: 'Ransom note language',
    description: 'Text typical of ransom notes.',
    re: /\b(?:your (?:files|documents|network) (?:have been|are) encrypted|to decrypt your files|bitcoin wallet|pay the ransom|decryptor)\b/gi,
  },
  // ---- Persistence
  {
    id: 'ioc.run-key', category: 'persistence', severity: 'high',
    title: 'Autorun registry key',
    description: 'Run / RunOnce / Winlogon keys start programs automatically at logon.',
    re: /(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)?\\?Software\\(?:WOW6432Node\\)?Microsoft\\Windows(?: NT)?\\CurrentVersion\\(?:Run(?:Once|Services)?|Winlogon|Image File Execution Options|Explorer\\Shell Folders)\b/gi,
  },
  {
    id: 'ioc.scheduled-task', category: 'persistence', severity: 'medium',
    title: 'Scheduled task creation',
    description: 'Scheduled tasks are a common persistence mechanism.',
    re: /\bschtasks(?:\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b|New-ScheduledTaskAction/gi,
  },
  {
    id: 'ioc.startup-folder', category: 'persistence', severity: 'medium',
    title: 'Startup folder reference',
    description: 'Files dropped into the Startup folder run at every logon.',
    re: /\\Start Menu\\Programs\\Startup\b|shell:startup/gi,
  },
  {
    id: 'ioc.uac-bypass', category: 'evasion', severity: 'high',
    title: 'UAC bypass technique',
    description: 'Registry hijacks used to elevate silently (fodhelper / eventvwr / computerdefaults).',
    re: /\\(?:ms-settings|mscfile|exefile)\\shell\\open\\command|fodhelper\.exe|computerdefaults\.exe|DelegateExecute/gi,
  },
  // ---- Credential theft
  {
    id: 'ioc.browser-creds', category: 'credentials', severity: 'high',
    title: 'Browser credential / cookie store paths',
    description: 'Paths to browser password databases, cookies and encryption keys (info-stealer behaviour).',
    re: /\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Opera Software\\Opera (?:Stable|GX Stable)|Yandex\\YandexBrowser|Vivaldi|Chromium)\\User Data\b|\b(?:Login Data|Web Data|Local State)\b(?=[^\n]{0,40}(?:Default|Profile|User Data|\\))|logins\.json|key4\.db|cookies\.sqlite|encrypted_key/gi,
  },
  {
    id: 'ioc.discord-storage', category: 'credentials', severity: 'high',
    title: 'Discord token storage path',
    description: 'Discord Local Storage / leveldb paths are read by token grabbers.',
    re: /(?:discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb|\\discord(?:canary|ptb)?\\(?:Local Storage|leveldb))/gi,
  },
  {
    id: 'ioc.wallets', category: 'credentials', severity: 'high',
    title: 'Cryptocurrency wallet targeting',
    description: 'References to wallet files or wallet browser-extension IDs.',
    re: /\bwallet\.dat\b|\\(?:Exodus|Electrum|Atomic|Armory|Coinomi|Guarda|Jaxx)\\|\bnkbihfbeogaeaoehlefnkodbefgpgknn\b|\bbfnaelmomeimhlpmgjnjophhpkkoljpa\b|\bhnfanknocfeofbddgcijnmhnfnkdnaad\b|\bfhbohimaelbohpjbbldcngcnapndodjp\b/gi,
  },
  {
    id: 'ioc.app-creds', category: 'credentials', severity: 'medium',
    title: 'Messenger / game / FTP client credential paths',
    description: 'Paths used by stealers to grab sessions from Telegram, Steam, FileZilla and similar clients.',
    re: /\\Telegram Desktop\\tdata|\bloginusers\.vdf\b|\bssfn\d+|FileZilla\\(?:recentservers|sitemanager)\.xml|\\\.minecraft\\launcher_accounts\.json|NordVPN\\|ProtonVPN\\|\\OpenVPN Connect\\profiles/gi,
  },
  // ---- Evasion
  {
    id: 'ioc.anti-vm', category: 'evasion', severity: 'medium',
    title: 'Virtual machine / sandbox detection strings',
    description: 'Checks for analysis environments so the malware can stay dormant.',
    re: /\b(?:VBoxService|VBoxTray|vboxhook|vmtoolsd|vmwaretray|vmsrvc|vmusrvc|prl_tools|xenservice|qemu-ga|SbieDll\.dll|cuckoomon|wine_get_unix_file_name|HARDWARE\\ACPI\\DSDT\\VBOX__|VMware Virtual Platform|VirtualBox Graphics)\b/gi,
  },
  {
    id: 'ioc.anti-analysis', category: 'evasion', severity: 'medium',
    title: 'Analysis tool detection',
    description: 'Process names of debuggers and monitoring tools that malware checks for.',
    re: /\b(?:wireshark|procmon|procexp|processhacker|x64dbg|x32dbg|ollydbg|ida64|idaq|ghidra|dnspy|fiddler|httpdebugger|tcpview|autoruns|pestudio|regshot)(?:\.exe)?\b/gi,
  },
  // ---- Obfuscation
  {
    id: 'ioc.base64-blob', category: 'obfuscation', severity: 'low',
    title: 'Large Base64 blob',
    description: 'Long Base64 strings can hide embedded payloads or scripts.',
    re: /[A-Za-z0-9+/]{400,}={0,2}/g,
    redact: (s) => `${s.slice(0, 48)}… (${s.length} chars)`,
  },
  {
    id: 'ioc.pe-in-base64', category: 'obfuscation', severity: 'high',
    title: 'Base64-encoded Windows executable',
    description: '"TVqQ" / "TVpQ" is the Base64 encoding of an MZ header: an embedded executable payload.',
    re: /\bTV(?:qQ|pQ|oA|qA)AAMAAAAEAAAA[A-Za-z0-9+/]{40,}/g,
    redact: (s) => `${s.slice(0, 40)}… (${s.length} chars)`,
  },
];

export function isPublicIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 192 && b === 0) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
  if (a === 203 && b === 0) return false;
  if (p.every((n) => n === 255)) return false;
  return true;
}

/**
 * Run all IOC rules on a text corpus.
 * @returns {Array<{rule: IocRule, matches: string[]}>}
 */
export function scanIocs(text, maxMatchesPerRule = 25) {
  const out = [];
  for (const rule of IOC_RULES) {
    rule.re.lastIndex = 0;
    const seen = new Set();
    let m;
    let guard = 0;
    while ((m = rule.re.exec(text)) !== null) {
      if (++guard > 20000) break;
      if (m[0].length === 0) {
        rule.re.lastIndex += 1;
        continue;
      }
      const value = m[0].replace(/[.,;)\]}>'"]+$/, '');
      if (rule.keep && !rule.keep(value)) continue;
      seen.add(value);
      if (seen.size >= maxMatchesPerRule) break;
    }
    if (seen.size > 0) {
      const matches = [...seen].map((v) => (rule.redact ? rule.redact(v) : v));
      out.push({ rule, matches });
    }
  }
  return out;
}
