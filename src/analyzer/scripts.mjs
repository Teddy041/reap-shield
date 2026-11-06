/**
 * Static rules for scripts: JavaScript / TypeScript (including Electron main,
 * preload and renderer code), Python, PowerShell and batch files.
 * Scripts are only read as text; they are never evaluated or imported.
 */

/**
 * @typedef {object} ScriptRule
 * @property {string} id
 * @property {string[]} langs  'js' | 'py' | 'ps' | 'bat' | 'any'
 * @property {RegExp} re       Global regex.
 * @property {string} category
 * @property {'info'|'low'|'medium'|'high'|'critical'} severity
 * @property {string} title
 * @property {string} description
 * @property {number} [minCount]  Required number of matches before the rule fires.
 * @property {boolean} [electron] Only meaningful for Electron applications.
 */

/** @type {ScriptRule[]} */
export const SCRIPT_RULES = [
  // ---------------- Electron hardening (BrowserWindow webPreferences)
  {
    id: 'electron.node-integration', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'nodeIntegration enabled',
    description: 'Renderer pages get full Node.js access. Any XSS or remote content becomes remote code execution.',
    re: /\bnodeIntegration\s*:\s*(?:true|!0)\b/g,
  },
  {
    id: 'electron.node-integration-sub', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'nodeIntegrationInSubFrames / InWorker enabled',
    description: 'Node.js is exposed to sub-frames or web workers.',
    re: /\bnodeIntegrationIn(?:SubFrames|Worker)\s*:\s*(?:true|!0)\b/g,
  },
  {
    id: 'electron.context-isolation-off', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'contextIsolation disabled',
    description: 'Preload scripts share the JavaScript world with web content, so pages can tamper with privileged code.',
    re: /\bcontextIsolation\s*:\s*(?:false|!1)\b/g,
  },
  {
    id: 'electron.sandbox-off', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'Renderer sandbox disabled',
    description: 'sandbox:false removes the Chromium OS-level sandbox from renderer processes.',
    re: /\bsandbox\s*:\s*(?:false|!1)\b/g,
  },
  {
    id: 'electron.no-sandbox-switch', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'Chromium sandbox disabled globally',
    description: 'The app appends --no-sandbox or disables the sandbox for every process.',
    re: /appendSwitch\(\s*['"`]no-sandbox['"`]|app\.disableSandbox\s*\(|--no-sandbox\b/g,
  },
  {
    id: 'electron.web-security-off', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'webSecurity disabled',
    description: 'Same-origin policy is turned off; any page can read any origin and load local files.',
    re: /\bwebSecurity\s*:\s*(?:false|!1)\b/g,
  },
  {
    id: 'electron.insecure-content', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'allowRunningInsecureContent enabled',
    description: 'HTTPS pages may execute scripts loaded over plain HTTP.',
    re: /\ballowRunningInsecureContent\s*:\s*(?:true|!0)\b/g,
  },
  {
    id: 'electron.remote-module', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'Remote module enabled',
    description: '@electron/remote / enableRemoteModule gives renderers synchronous access to main-process objects.',
    re: /\benableRemoteModule\s*:\s*(?:true|!0)\b|require\(\s*['"]@electron\/remote(?:\/main)?['"]\s*\)|\.enable\(\s*\w+\.webContents\s*\)/g,
  },
  {
    id: 'electron.webview-tag', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: '<webview> tag enabled',
    description: 'webviewTag:true lets renderer content embed guest pages with their own preferences.',
    re: /\bwebviewTag\s*:\s*(?:true|!0)\b/g,
  },
  {
    id: 'electron.experimental', langs: ['js'], electron: true, category: 'electron', severity: 'low',
    title: 'Experimental Blink features enabled',
    description: 'experimentalFeatures / enableBlinkFeatures widen the renderer attack surface.',
    re: /\bexperimentalFeatures\s*:\s*(?:true|!0)\b|\benableBlinkFeatures\s*:/g,
  },
  {
    id: 'electron.expose-ipc-raw', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'Raw ipcRenderer exposed to the page',
    description: 'exposeInMainWorld passes the ipcRenderer object (or a generic send/invoke wrapper) to web content, so any page script can call every IPC channel.',
    re: /exposeInMainWorld\s*\([^)]{0,200}?\bipcRenderer\s*[,}]|\bipcRenderer\s*:\s*ipcRenderer\b|window\.ipcRenderer\s*=\s*(?:require\(\s*['"]electron['"]\s*\)\.)?ipcRenderer/g,
  },
  {
    id: 'electron.ipc-passthrough', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'Unrestricted IPC channel passthrough',
    description: 'A preload helper forwards caller-chosen channel names to ipcRenderer.invoke/send without an allow-list.',
    re: /\(\s*(\w+)\s*(?:,\s*\.\.\.\s*\w+)?\s*\)\s*=>\s*ipcRenderer\.(?:invoke|send|sendSync|on)\(\s*\1\s*[,)]/g,
  },
  {
    id: 'electron.ipc-handlers', langs: ['js'], electron: true, category: 'electron', severity: 'info',
    title: 'IPC handlers registered in main process',
    description: 'ipcMain handlers define the privileged API surface. Each should validate event.senderFrame and its arguments.',
    re: /\bipcMain\.(?:handle|handleOnce|on|once)\s*\(\s*['"`][^'"`]{1,120}['"`]/g,
  },
  {
    id: 'electron.ipc-renderer-calls', langs: ['js'], electron: true, category: 'electron', severity: 'info',
    title: 'Renderer IPC calls',
    description: 'ipcRenderer.invoke / send calls found in preload or renderer code.',
    re: /\bipcRenderer\.(?:invoke|send|sendSync|sendTo|postMessage)\s*\(\s*['"`][^'"`]{1,120}['"`]/g,
  },
  {
    id: 'electron.ipc-dangerous-handler', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'IPC handler reaches a dangerous sink',
    description: 'An ipcMain handler body passes renderer-controlled data to shell, child_process, fs writes or eval.',
    re: /ipcMain\.(?:handle|on)\s*\([^)]{0,120}?,\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{[^}]{0,600}?\b(?:shell\.openExternal|shell\.openPath|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(|fs\.(?:writeFile|unlink|rm)\w*\s*\(|eval\s*\(|new Function)/g,
  },
  {
    id: 'electron.open-external', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'shell.openExternal with a dynamic URL',
    description: 'Opening non-constant URLs can launch arbitrary protocol handlers (file:, smb:, custom schemes).',
    re: /shell\.openExternal\s*\(\s*(?!['"`]https:\/\/)[^)]{1,120}\)/g,
  },
  {
    id: 'electron.execute-javascript', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'webContents.executeJavaScript',
    description: 'Main process injects code into a page; dangerous if the string contains untrusted data.',
    re: /\.executeJavaScript(?:InIsolatedWorld)?\s*\(/g,
  },
  {
    id: 'electron.insecure-load', langs: ['js'], electron: true, category: 'electron', severity: 'medium',
    title: 'Window loads remote content over plain HTTP',
    description: 'loadURL over http:// allows network attackers to inject code into a privileged window.',
    re: /\.loadURL\(\s*['"`]http:\/\/(?!localhost|127\.0\.0\.1)[^'"`]+['"`]/g,
  },
  {
    id: 'electron.cert-bypass', langs: ['js'], electron: true, category: 'electron', severity: 'high',
    title: 'TLS certificate validation bypass',
    description: 'certificate-error handlers that call callback(true) or ignore-certificate-errors disable TLS validation.',
    re: /on\(\s*['"]certificate-error['"][^]{0,300}?callback\(\s*true\s*\)|appendSwitch\(\s*['"]ignore-certificate-errors['"]|setCertificateVerifyProc\(\s*\([^)]*\)\s*=>\s*\w+\(\s*0\s*\)/g,
  },
  {
    id: 'electron.devtools-prod', langs: ['js'], electron: true, category: 'electron', severity: 'low',
    title: 'DevTools opened programmatically',
    description: 'openDevTools() in shipped code exposes internals to end users.',
    re: /\.openDevTools\s*\(/g,
  },

  // ---------------- JavaScript generic
  {
    id: 'js.eval', langs: ['js'], category: 'execution', severity: 'medium',
    title: 'Dynamic code evaluation (eval / new Function)',
    description: 'Executes strings as code; common in loaders and obfuscated malware.',
    re: /(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext|Script)\s*\(/g,
  },
  {
    id: 'js.decode-exec', langs: ['js'], category: 'obfuscation', severity: 'high',
    title: 'Decoded payload executed at runtime',
    description: 'Base64 / hex / char-code decoding fed directly into eval or Function.',
    re: /(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/g,
  },
  {
    id: 'js.child-process', langs: ['js'], category: 'execution', severity: 'medium',
    title: 'Spawns OS commands (child_process)',
    description: 'exec / spawn / execSync run shell commands from JavaScript.',
    re: /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|\b(?:execSync|spawnSync|execFileSync)\s*\(/g,
  },
  {
    id: 'js.shell-cmd', langs: ['js'], category: 'execution', severity: 'high',
    title: 'Hidden shell / PowerShell invocation',
    description: 'Runs cmd or PowerShell, often with hidden windows or execution-policy bypass.',
    re: /\b(?:exec|spawn|execSync|execFile)\s*\(\s*['"`](?:cmd(?:\.exe)?\s+\/c|powershell(?:\.exe)?[^'"`]{0,80}(?:-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|-nop\b))/gi,
  },
  {
    id: 'js.obfuscator-io', langs: ['js'], category: 'obfuscation', severity: 'high',
    title: 'javascript-obfuscator style identifiers',
    description: 'Hundreds of _0x-prefixed hex identifiers indicate obfuscator.io output, which is rare in legitimate apps.',
    re: /\b_0x[a-f0-9]{4,6}\b/g,
    minCount: 150,
  },
  {
    id: 'js.char-code-wall', langs: ['js'], category: 'obfuscation', severity: 'medium',
    title: 'Large String.fromCharCode payload',
    description: 'Long character-code arrays hide strings from static inspection.',
    re: /String\.fromCharCode\s*\((?:\s*\d{2,3}\s*,){40,}/g,
  },
  {
    id: 'js.startup-write', langs: ['js'], category: 'persistence', severity: 'high',
    title: 'Writes into the Windows Startup folder',
    description: 'File writes targeting the Startup folder achieve persistence.',
    re: /Start Menu[\\/]+Programs[\\/]+Startup|['"`]shell:startup/gi,
  },
  {
    id: 'js.reg-add', langs: ['js', 'any'], category: 'persistence', severity: 'high',
    title: 'Registry modification via reg.exe',
    description: 'Shells out to reg add / reg delete.',
    re: /\breg(?:\.exe)?\s+(?:add|delete)\s+["']?HK/gi,
  },
  {
    id: 'js.token-grab', langs: ['js', 'py'], category: 'credentials', severity: 'critical',
    title: 'Discord / browser token grabbing logic',
    description: 'Reads leveldb / Local Storage files and searches them with a token regex: classic token grabber.',
    re: /(?:leveldb|Local Storage)[^]{0,600}?(?:\[\\w-\]\{24\}|\[a-zA-Z0-9_-\]\{2[34]\}|mfa\\\.|dQw4w9WgXcQ)/g,
  },
  {
    id: 'js.npm-install-hook', langs: ['js'], category: 'execution', severity: 'medium',
    title: 'npm lifecycle script runs code at install time',
    description: 'preinstall / postinstall hooks run automatically during npm install (supply-chain vector).',
    re: /"(?:preinstall|install|postinstall)"\s*:\s*"[^"]{3,}"/g,
  },

  // ---------------- Python
  {
    id: 'py.exec', langs: ['py'], category: 'execution', severity: 'medium',
    title: 'Dynamic code execution (exec / eval / compile)',
    description: 'Executes strings as Python code.',
    re: /(?<![\w.])(?:exec|eval)\s*\(|\bcompile\s*\([^)]*['"]exec['"]/g,
  },
  {
    id: 'py.decode-exec', langs: ['py'], category: 'obfuscation', severity: 'high',
    title: 'Decoded or decompressed payload executed',
    description: 'base64 / zlib / marshal / lzma decoding passed straight to exec, typical of droppers and crypters.',
    re: /\bexec\s*\(\s*(?:__import__\(\s*['"](?:base64|zlib|marshal|lzma|bz2|codecs)['"]\s*\)|base64\.|zlib\.|marshal\.|lzma\.|bz2\.|codecs\.decode)/g,
  },
  {
    id: 'py.marshal-loads', langs: ['py'], category: 'obfuscation', severity: 'high',
    title: 'marshal.loads code object',
    description: 'Loads pre-compiled bytecode, a common way to hide Python malware.',
    re: /\bmarshal\.loads\s*\(/g,
  },
  {
    id: 'py.pyarmor', langs: ['py'], category: 'obfuscation', severity: 'medium',
    title: 'PyArmor / commercial obfuscation',
    description: 'The script is protected by PyArmor or a similar obfuscator.',
    re: /__pyarmor__|pyarmor_runtime|\bPyarmor\b/g,
  },
  {
    id: 'py.subprocess', langs: ['py'], category: 'execution', severity: 'medium',
    title: 'Runs OS commands',
    description: 'subprocess / os.system / os.popen executes shell commands.',
    re: /\bsubprocess\.(?:Popen|call|run|check_output|check_call|getoutput)\s*\(|\bos\.(?:system|popen|startfile|exec[lv]p?e?)\s*\(/g,
  },
  {
    id: 'py.shellcode', langs: ['py'], category: 'execution', severity: 'critical',
    title: 'Shellcode loader via ctypes',
    description: 'Allocates executable memory and runs raw bytes through ctypes (classic Python shellcode loader).',
    re: /ctypes\.(?:windll|WinDLL)[^\n]{0,80}\b(?:VirtualAlloc|VirtualProtect|CreateThread|RtlMoveMemory|WriteProcessMemory)\b|kernel32\.(?:VirtualAlloc|CreateThread|RtlMoveMemory)\s*\(/g,
  },
  {
    id: 'py.pickle', langs: ['py'], category: 'execution', severity: 'medium',
    title: 'Unsafe deserialization (pickle / marshal / yaml.load)',
    description: 'Deserializing untrusted data with pickle or yaml.load executes code.',
    re: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g,
  },
  {
    id: 'py.winreg-run', langs: ['py'], category: 'persistence', severity: 'high',
    title: 'Registry autorun persistence (winreg)',
    description: 'Writes values through winreg, commonly to the Run key.',
    re: /\bwinreg\.SetValueEx\s*\(|\b_winreg\.SetValueEx\s*\(/g,
  },
  {
    id: 'py.keylogger', langs: ['py'], category: 'credentials', severity: 'high',
    title: 'Keyboard capture library',
    description: 'pynput / keyboard hooks capture keystrokes.',
    re: /\bfrom\s+pynput(?:\.keyboard)?\s+import\b|\bkeyboard\.on_press\b|\bpyHook\b|\bGetAsyncKeyState\b/g,
  },
  {
    id: 'py.screen-capture', langs: ['py'], category: 'credentials', severity: 'low',
    title: 'Screen capture',
    description: 'Takes screenshots (spyware / stealer behaviour when combined with exfiltration).',
    re: /\bImageGrab\.grab\s*\(|\bpyautogui\.screenshot\s*\(|\bmss\(\)\.grab\b/g,
  },
  {
    id: 'py.browser-decrypt', langs: ['py'], category: 'credentials', severity: 'critical',
    title: 'Browser password / cookie decryption',
    description: 'Uses DPAPI (CryptUnprotectData) or AES-GCM with the Chrome "encrypted_key" to decrypt saved passwords.',
    re: /win32crypt\.CryptUnprotectData|CryptUnprotectData\s*\(|['"]encrypted_key['"]/g,
  },

  // ---------------- PowerShell / batch / VBS
  {
    id: 'ps.hidden-bypass', langs: ['ps', 'bat', 'any'], category: 'execution', severity: 'high',
    title: 'Hidden PowerShell with execution-policy bypass',
    description: 'Runs PowerShell hidden and bypasses execution policy, typical in droppers.',
    re: /powershell(?:\.exe)?[^\n]{0,120}(?:-w(?:indowstyle)?\s+h(?:idden)?)[^\n]{0,120}|powershell(?:\.exe)?[^\n]{0,80}-(?:ep|exec(?:utionpolicy)?)\s+bypass/gi,
  },
  {
    id: 'vbs.wscript-shell', langs: ['any'], category: 'execution', severity: 'medium',
    title: 'WScript.Shell / Shell.Application execution',
    description: 'Script host objects that run commands.',
    re: /CreateObject\(\s*["'](?:WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP|ADODB\.Stream)["']\s*\)/gi,
  },

  // ---------------- Office VBA macros (decompressed module source)
  {
    id: 'vba.autoexec', langs: ['vba'], category: 'execution', severity: 'medium',
    title: 'Macro runs automatically',
    description: 'Auto-execution entry points (AutoOpen, Document_Open, Workbook_Open, ...) run code as soon as macros are enabled.',
    re: /\b(?:Auto_?Open|AutoExec|AutoClose|Auto_Close|Document_Open|Document_Close|DocumentOpen|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|Presentation_Open|InkPicture1_Painted)\b/gi,
  },
  {
    id: 'vba.shell', langs: ['vba'], category: 'execution', severity: 'high',
    title: 'Macro executes commands',
    description: 'Shell / WScript.Shell / ShellExecute / CreateProcess / WMI process creation from VBA.',
    re: /\bShell\s*\(|\bShell\s+["\w]|\.ShellExecute\b|\.Run\s*\(?\s*["\w]|\bCreateProcess[AW]?\b|Win32_Process|\bMacScript\b|\bExecuteExcel4Macro\b/gi,
  },
  {
    id: 'vba.download', langs: ['vba'], category: 'network', severity: 'high',
    title: 'Macro downloads content',
    description: 'XMLHTTP / WinHttp / URLDownloadToFile / ADODB.Stream used to fetch and save a payload.',
    re: /URLDownloadToFile[AW]?|MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP|\.responseBody\b|ADODB\.Stream|\.SaveToFile\b/gi,
  },
  {
    id: 'vba.win32-api', langs: ['vba'], category: 'execution', severity: 'high',
    title: 'Macro declares Windows API functions',
    description: 'Declare statements importing kernel32 / ntdll functions, used for in-memory shellcode execution from Office.',
    re: /\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+\w+\s+Lib\s+"(?:kernel32|ntdll|user32|shell32|urlmon)/gi,
  },
  {
    id: 'vba.obfuscation', langs: ['vba'], category: 'obfuscation', severity: 'medium',
    title: 'Obfuscated macro strings',
    description: 'Heavy Chr()/StrReverse/Replace concatenation hides the real strings.',
    re: /\b(?:Chr[BW]?\$?\s*\(\s*\d+\s*\)\s*&|StrReverse\s*\(|ChrW?\(\s*\d+\s*(?:Xor|-|\+)\s*\d+\s*\))/gi,
    minCount: 15,
  },
  {
    id: 'vba.environ', langs: ['vba'], category: 'fileops', severity: 'low',
    title: 'Macro writes to user folders',
    description: 'Environ("TEMP"/"APPDATA") combined with file writes is typical of droppers.',
    re: /Environ\$?\(\s*"(?:TEMP|TMP|APPDATA|USERPROFILE|PUBLIC|ALLUSERSPROFILE)"\s*\)/gi,
  },

  // ---------------- Office containers / HTML / misc
  {
    id: 'office.template-injection', langs: ['any', 'js'], category: 'network', severity: 'high',
    title: 'Remote template injection',
    description: 'The document loads a template or OLE object from a remote URL when opened (bypasses macro-in-file detection).',
    re: /Type="[^"]*\/(?:attachedTemplate|oleObject|frame|subDocument)"[^>]{0,300}?Target="(?:https?:|\\\\|file:)[^"]+"[^>]{0,80}?TargetMode="External"|Target="(?:https?:|\\\\)[^"]+"[^>]{0,80}?TargetMode="External"[^>]{0,200}?Type="[^"]*\/(?:attachedTemplate|oleObject|frame)"/gi,
  },
  {
    id: 'office.follina', langs: ['any', 'js'], category: 'execution', severity: 'critical',
    title: 'ms-msdt / search-ms protocol abuse (Follina-style)',
    description: 'Office and HTML documents that invoke ms-msdt or search-ms handlers can execute code without macros.',
    re: /ms-msdt:[^"'\s]{0,40}\/id\s+PCWDiagnostic|ms-msdt:\/?id|IT_BrowseForFile=|search-ms:query=/gi,
  },
  {
    id: 'office.dde', langs: ['any', 'js'], category: 'execution', severity: 'high',
    title: 'DDE / DDEAUTO field',
    description: 'Dynamic Data Exchange fields can launch commands from documents without macros.',
    re: /\b(?:DDEAUTO|DDE)\b\s*"?[^"\n]{0,60}(?:cmd|powershell|mshta|c:\\\\)/gi,
  },
  {
    id: 'html.smuggling', langs: ['js'], category: 'evasion', severity: 'high',
    title: 'HTML smuggling',
    description: 'The page assembles a file from embedded data (Blob / base64) and forces a download, bypassing mail and web gateways.',
    re: /(?:msSaveOrOpenBlob|URL\.createObjectURL)\s*\([^]{0,600}?\.download\s*=|new\s+Blob\s*\(\s*\[[^\]]{0,200}?(?:atob|Uint8Array|base64)|\.download\s*=[^;]{0,120};[^]{0,300}?\.click\s*\(\s*\)[^]{0,200}?(?:atob|Blob)/g,
  },
  {
    id: 'script.encoded', langs: ['any'], category: 'obfuscation', severity: 'high',
    title: 'Microsoft Script Encoder (JSE / VBE) content',
    description: 'Encoded JScript/VBScript ("#@~^") is almost exclusively used to hide malicious scripts.',
    re: /#@~\^[A-Za-z0-9+/]{6}==/g,
  },
  {
    id: 'script.unc-ntlm', langs: ['any', 'js'], category: 'credentials', severity: 'medium',
    title: 'Remote UNC / file path that leaks NTLM credentials',
    description: '.url / .scf / .library-ms / HTML references to \\\\host\\share make Windows authenticate to a remote server automatically.',
    re: /(?:URL|IconFile|IconResource)\s*=\s*(?:file:\/*)?\\\\[\w.-]+\\|<(?:img|link|iframe)[^>]{0,80}(?:src|href)=["']?(?:file:\/*)?\\\\[\w.-]+\\/gi,
  },
];

/** Map a file extension to rule languages. */
export function scriptLang(ext) {
  if (['.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.html', '.htm', '.hta', '.svg', '.sct', '.wsf', '.xhtml', '.mht', '.mhtml', '.json'].includes(ext)) return 'js';
  if (ext === '.py' || ext === '.pyw') return 'py';
  if (ext === '.ps1' || ext === '.psm1' || ext === '.psd1') return 'ps';
  if (ext === '.bat' || ext === '.cmd') return 'bat';
  if (['.vbs', '.vba', '.bas', '.cls', '.frm'].includes(ext)) return 'vba';
  return 'other';
}

/** Build a line-number lookup (binary search over newline offsets). */
function lineIndex(text) {
  let starts = null;
  return (index) => {
    if (!starts) {
      starts = [0];
      for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
    }
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

function snippet(text, index, length) {
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + Math.min(length, 160) + 40);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

/**
 * Run script rules against a text.
 * @param {string} text
 * @param {string} lang
 * @param {{electron: boolean}} ctx
 * @returns {Array<{rule: ScriptRule, count: number, samples: Array<{line:number, text:string}>}>}
 */
export function scanScript(text, lang, ctx) {
  const results = [];
  const lineOf = lineIndex(text);
  for (const rule of SCRIPT_RULES) {
    if (!rule.langs.includes(lang) && !rule.langs.includes('any')) continue;
    if (rule.electron && !ctx.electron) continue;
    rule.re.lastIndex = 0;
    let count = 0;
    const samples = [];
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      if (m[0].length === 0) {
        rule.re.lastIndex += 1;
        continue;
      }
      count += 1;
      if (samples.length < 5) samples.push({ index: m.index, length: m[0].length });
      if (count > 5000) break;
    }
    if (count >= (rule.minCount ?? 1)) {
      results.push({
        rule,
        count,
        samples: samples.map((s) => ({ line: lineOf(s.index), text: snippet(text, s.index, s.length) })),
      });
    }
  }
  return results;
}

/** Heuristic: does this file tree belong to an Electron application? */
export function looksLikeElectron(text) {
  return /require\(\s*['"]electron['"]\s*\)|from\s+['"]electron['"]|\bBrowserWindow\b|\bipcMain\b|\bcontextBridge\b|"electron"\s*:/.test(text);
}

/** Heuristic minification / packing check for a script. */
export function scriptShape(text) {
  const lines = text.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  return { lines: lines.length, longestLine: longest, minified: longest > 5000 && lines.length < 50 };
}
