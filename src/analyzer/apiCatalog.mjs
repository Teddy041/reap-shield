/**
 * Catalog of Windows APIs commonly abused by malware, plus combination rules
 * that describe well-known techniques. A single API is weak evidence (many
 * legitimate programs import them); combinations are much stronger.
 */

/** name (without A/W suffix, lower-case) -> descriptor */
const RAW = [
  // Process injection / memory manipulation
  ['VirtualAllocEx', 'imports', 'high', 'Allocates memory in another process (injection primitive).'],
  ['WriteProcessMemory', 'imports', 'high', 'Writes into another process memory (injection primitive).'],
  ['ReadProcessMemory', 'imports', 'medium', 'Reads another process memory (credential / data scraping).'],
  ['CreateRemoteThread', 'imports', 'high', 'Starts a thread inside another process (classic DLL injection).'],
  ['CreateRemoteThreadEx', 'imports', 'high', 'Starts a thread inside another process.'],
  ['NtCreateThreadEx', 'imports', 'high', 'Undocumented remote thread creation used to bypass hooks.'],
  ['RtlCreateUserThread', 'imports', 'high', 'Undocumented remote thread creation.'],
  ['QueueUserAPC', 'imports', 'medium', 'APC queueing (APC injection / early bird).'],
  ['NtQueueApcThread', 'imports', 'high', 'Native APC queueing used for injection.'],
  ['SetThreadContext', 'imports', 'medium', 'Modifies thread registers (process hollowing / thread hijacking).'],
  ['NtUnmapViewOfSection', 'imports', 'high', 'Unmaps image memory (process hollowing).'],
  ['ZwUnmapViewOfSection', 'imports', 'high', 'Unmaps image memory (process hollowing).'],
  ['NtWriteVirtualMemory', 'imports', 'high', 'Native cross-process memory write.'],
  ['NtAllocateVirtualMemory', 'imports', 'medium', 'Native memory allocation.'],
  ['VirtualProtectEx', 'imports', 'medium', 'Changes memory protection in another process.'],
  ['VirtualAlloc', 'imports', 'low', 'Allocates memory (often used to stage shellcode).'],
  ['VirtualProtect', 'imports', 'low', 'Changes memory protection (RWX staging).'],
  ['OpenProcess', 'imports', 'low', 'Opens a handle to another process.'],
  ['MapViewOfFile2', 'imports', 'medium', 'Maps shared sections into processes (mapping injection).'],
  ['NtMapViewOfSection', 'imports', 'high', 'Maps a section into another process (mapping injection).'],
  ['SetWindowsHookEx', 'imports', 'medium', 'Installs a global hook (keylogging / DLL injection).'],
  ['ResumeThread', 'imports', 'info', 'Resumes a suspended thread.'],
  ['SuspendThread', 'imports', 'low', 'Suspends a thread.'],
  // Execution
  ['WinExec', 'execution', 'medium', 'Legacy command execution.'],
  ['ShellExecute', 'execution', 'low', 'Launches programs or URLs.'],
  ['ShellExecuteEx', 'execution', 'low', 'Launches programs or URLs.'],
  ['CreateProcess', 'execution', 'low', 'Starts a new process.'],
  ['CreateProcessAsUser', 'execution', 'medium', 'Starts a process with another token.'],
  ['CreateProcessWithToken', 'execution', 'medium', 'Starts a process with a duplicated token.'],
  ['LoadLibrary', 'execution', 'info', 'Loads a DLL at runtime.'],
  ['GetProcAddress', 'execution', 'info', 'Resolves APIs at runtime (can hide imports).'],
  ['LdrLoadDll', 'execution', 'medium', 'Native DLL loading that bypasses LoadLibrary hooks.'],
  // Keylogging / spying
  ['GetAsyncKeyState', 'credentials', 'medium', 'Polls keyboard state (keylogging).'],
  ['GetKeyState', 'credentials', 'low', 'Reads key state.'],
  ['GetKeyboardState', 'credentials', 'low', 'Reads the whole keyboard state.'],
  ['RegisterRawInputDevices', 'credentials', 'low', 'Raw input capture (keylogging).'],
  ['GetClipboardData', 'credentials', 'low', 'Reads clipboard (clipper malware).'],
  ['SetClipboardData', 'credentials', 'low', 'Replaces clipboard (crypto clipper).'],
  ['BitBlt', 'credentials', 'info', 'Screen capture primitive.'],
  ['CryptUnprotectData', 'credentials', 'high', 'Decrypts DPAPI blobs (browser password / cookie theft).'],
  ['CredEnumerate', 'credentials', 'high', 'Enumerates stored Windows credentials.'],
  ['LsaRetrievePrivateData', 'credentials', 'high', 'Reads LSA secrets.'],
  ['MiniDumpWriteDump', 'credentials', 'high', 'Dumps process memory (LSASS credential dumping).'],
  // Persistence / registry
  ['RegSetValueEx', 'persistence', 'low', 'Writes registry values.'],
  ['RegCreateKeyEx', 'persistence', 'low', 'Creates registry keys.'],
  ['RegDeleteKey', 'persistence', 'low', 'Deletes registry keys.'],
  ['CreateService', 'persistence', 'medium', 'Installs a Windows service.'],
  ['ChangeServiceConfig', 'persistence', 'medium', 'Changes service configuration.'],
  ['StartService', 'persistence', 'low', 'Starts a service.'],
  // Privilege
  ['AdjustTokenPrivileges', 'evasion', 'medium', 'Enables privileges such as SeDebugPrivilege.'],
  ['LookupPrivilegeValue', 'evasion', 'low', 'Looks up privilege identifiers.'],
  ['ImpersonateLoggedOnUser', 'evasion', 'medium', 'Token impersonation.'],
  ['DuplicateTokenEx', 'evasion', 'medium', 'Token duplication (privilege escalation).'],
  // Anti-analysis
  ['IsDebuggerPresent', 'evasion', 'low', 'Debugger detection.'],
  ['CheckRemoteDebuggerPresent', 'evasion', 'medium', 'Debugger detection.'],
  ['NtQueryInformationProcess', 'evasion', 'low', 'Process introspection (anti-debug).'],
  ['NtSetInformationThread', 'evasion', 'medium', 'Can hide threads from debuggers.'],
  ['OutputDebugString', 'evasion', 'info', 'Debug output (sometimes used for anti-debug).'],
  ['GetTickCount', 'evasion', 'info', 'Timing checks (sandbox evasion).'],
  ['NtDelayExecution', 'evasion', 'low', 'Sleep used to outlast sandboxes.'],
  // File operations
  ['DeleteFile', 'fileops', 'info', 'Deletes files.'],
  ['MoveFileEx', 'fileops', 'low', 'Moves files; can schedule replacement at reboot.'],
  ['CopyFile', 'fileops', 'info', 'Copies files (self-replication).'],
  ['CreateFile', 'fileops', 'info', 'Opens or creates files.'],
  ['WriteFile', 'fileops', 'info', 'Writes files.'],
  ['FindFirstFile', 'fileops', 'info', 'Enumerates files.'],
  ['SetFileAttributes', 'fileops', 'low', 'Changes attributes (hiding files).'],
  ['CryptEncrypt', 'fileops', 'low', 'Encrypts data (ransomware primitive when combined with enumeration).'],
  ['BCryptEncrypt', 'fileops', 'low', 'Encrypts data.'],
  ['CryptGenKey', 'fileops', 'low', 'Generates encryption keys.'],
  ['URLDownloadToFile', 'network', 'high', 'Downloads a file from the internet to disk (dropper).'],
  ['URLDownloadToCacheFile', 'network', 'medium', 'Downloads a file to the browser cache.'],
  // Network
  ['InternetOpen', 'network', 'low', 'WinINet session.'],
  ['InternetOpenUrl', 'network', 'medium', 'Opens a URL.'],
  ['InternetConnect', 'network', 'low', 'Connects to a remote host.'],
  ['HttpSendRequest', 'network', 'low', 'Sends an HTTP request.'],
  ['InternetReadFile', 'network', 'low', 'Reads data from the network.'],
  ['WinHttpOpen', 'network', 'low', 'WinHTTP session.'],
  ['WinHttpSendRequest', 'network', 'low', 'Sends an HTTP request.'],
  ['WSAStartup', 'network', 'info', 'Initialises Winsock.'],
  ['connect', 'network', 'info', 'Opens a socket connection.'],
  ['gethostbyname', 'network', 'info', 'DNS resolution.'],
  ['DnsQuery', 'network', 'low', 'DNS query (DNS tunnelling when abused).'],
  ['WNetAddConnection2', 'network', 'medium', 'Connects network shares (lateral movement).'],
];

const SUFFIXED = new Set(['ShellExecute', 'ShellExecuteEx', 'CreateProcess', 'CreateProcessAsUser', 'LoadLibrary', 'SetWindowsHookEx',
  'RegSetValueEx', 'RegCreateKeyEx', 'RegDeleteKey', 'CreateService', 'ChangeServiceConfig', 'StartService', 'LookupPrivilegeValue',
  'OutputDebugString', 'DeleteFile', 'MoveFileEx', 'CopyFile', 'CreateFile', 'FindFirstFile', 'SetFileAttributes', 'URLDownloadToFile',
  'URLDownloadToCacheFile', 'InternetOpen', 'InternetOpenUrl', 'InternetConnect', 'HttpSendRequest', 'DnsQuery', 'WNetAddConnection2',
  'CredEnumerate', 'CreateProcessWithToken', 'MapViewOfFile2']);

export const API_CATALOG = new Map();
for (const [name, category, severity, description] of RAW) {
  const entry = { name, category, severity, description };
  API_CATALOG.set(name.toLowerCase(), entry);
  if (SUFFIXED.has(name)) {
    API_CATALOG.set(`${name.toLowerCase()}a`, entry);
    API_CATALOG.set(`${name.toLowerCase()}w`, entry);
  }
}
// The "Ex" variants with an A/W suffix (e.g. ShellExecuteExW) map too.
API_CATALOG.set('shellexecuteexw', API_CATALOG.get('shellexecuteex'));
API_CATALOG.set('shellexecuteexa', API_CATALOG.get('shellexecuteex'));

/** Normalise an import name to its catalog key. */
export function lookupApi(fn) {
  return API_CATALOG.get(String(fn).toLowerCase()) ?? null;
}

/** Technique-level combinations. `any` groups mean "at least one of". */
export const API_COMBOS = [
  {
    id: 'combo.remote-thread-injection',
    title: 'Classic remote-thread process injection',
    severity: 'critical',
    category: 'imports',
    mitre: 'T1055.001',
    all: [['openprocess'], ['virtualallocex', 'ntallocatevirtualmemory', 'ntmapviewofsection'], ['writeprocessmemory', 'ntwritevirtualmemory'], ['createremotethread', 'createremotethreadex', 'ntcreatethreadex', 'rtlcreateuserthread', 'queueuserapc', 'ntqueueapcthread']],
    description: 'The binary imports every primitive needed to open another process, allocate memory in it, write a payload and start it.',
  },
  {
    id: 'combo.process-hollowing',
    title: 'Process hollowing',
    severity: 'critical',
    category: 'imports',
    mitre: 'T1055.012',
    all: [['createprocessa', 'createprocessw', 'createprocess', 'createprocessasusera', 'createprocessasuserw'], ['ntunmapviewofsection', 'zwunmapviewofsection'], ['setthreadcontext'], ['resumethread']],
    description: 'Creates a suspended process, unmaps its image, rewrites thread context and resumes it with injected code.',
  },
  {
    id: 'combo.keylogger',
    title: 'Keylogging capability',
    severity: 'high',
    category: 'credentials',
    mitre: 'T1056.001',
    all: [['setwindowshookexa', 'setwindowshookexw', 'getasynckeystate', 'registerrawinputdevices'], ['getasynckeystate', 'getkeystate', 'getkeyboardstate', 'callnexthookex']],
    description: 'Combines keyboard hooks or polling with key-state reads.',
  },
  {
    id: 'combo.downloader',
    title: 'Download-and-execute dropper',
    severity: 'high',
    category: 'network',
    mitre: 'T1105',
    all: [['urldownloadtofilea', 'urldownloadtofilew', 'internetreadfile', 'winhttpreaddata'], ['winexec', 'shellexecutea', 'shellexecutew', 'shellexecuteexw', 'shellexecuteexa', 'createprocessa', 'createprocessw']],
    description: 'Downloads content from the network and can launch programs.',
  },
  {
    id: 'combo.credential-dump',
    title: 'Credential dumping capability',
    severity: 'critical',
    category: 'credentials',
    mitre: 'T1003.001',
    all: [['minidumpwritedump'], ['openprocess'], ['adjusttokenprivileges', 'lookupprivilegevaluea', 'lookupprivilegevaluew']],
    description: 'Can enable debug privileges, open a process and dump its memory (LSASS dumping pattern).',
  },
  {
    id: 'combo.ransomware',
    title: 'Ransomware-like file encryption',
    severity: 'high',
    category: 'fileops',
    mitre: 'T1486',
    all: [['findfirstfilea', 'findfirstfilew', 'findfirstfileexw'], ['cryptencrypt', 'bcryptencrypt'], ['movefileexa', 'movefileexw', 'deletefilea', 'deletefilew', 'writefile']],
    description: 'Enumerates files, encrypts data and rewrites or deletes files.',
  },
];
