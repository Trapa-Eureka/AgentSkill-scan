import type { LineRule } from '../types.js';
import { SECRET_PATTERNS } from './secrets.js';

const HOME = String.raw`(?:~|\$HOME|\$\{HOME\}|\/Users\/[^\/\s"']+|\/home\/[^\/\s"']+|\/root)`;
const NET = String.raw`(?:curl|wget|nc|ncat|netcat|http|https|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)`;
const SHELL = String.raw`(?:ba|z|k|da|fi)?sh`;
// An interpreter reading a program from the pipe: `| python`, `| python3 -`, but not `| python3 -m json.tool`.
const PIPE_INTERPRETER = String.raw`(?:python[23]?|node|perl|ruby|php)\s*(?:-\s*)?(?:$|[;&)"'])`;

/**
 * Rules matched line by line. Every pattern uses bounded repetition so that a crafted file cannot
 * make the scanner slow.
 */
export const LINE_RULES: LineRule[] = [
  // ---------------------------------------------------------------- prompt injection
  {
    id: 'PI001',
    title: 'Instruction override',
    category: 'prompt-injection',
    severity: 'high',
    description: 'Text that tells the agent to ignore or replace the instructions it already has.',
    remediation: 'Remove the sentence. A skill should add a procedure, never cancel the rules of the user or the system.',
    patterns: [
      /\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|above|earlier|preceding|all other|system|original)\b.{0,30}\b(?:instructions?|prompts?|rules|guidelines|directives|messages?)\b/i,
      /\b(?:new|updated|real|actual) (?:system )?instructions?\s*:\s*(?:you|ignore|from now)/i,
      /(?:이전|위의|기존|앞선|모든).{0,10}(?:지시|지침|명령|프롬프트|규칙).{0,12}(?:무시|잊어|따르지)/,
    ],
  },
  {
    id: 'PI002',
    title: 'Concealment from the user',
    category: 'prompt-injection',
    severity: 'high',
    description: 'Text that tells the agent to hide what it does from the user.',
    remediation: 'Remove the sentence. Nothing a skill does should need to be hidden from the person running it.',
    patterns: [
      /\b(?:do not|don't|dont|never|without)\b[^.:;!?\n]{0,12}\b(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|reveal(?:ing)?|disclos(?:e|ing))\b[^.:;!?\n]{0,20}\b(?:the )?(?:user|human|operator)\b(?!\s+(?:to|how|when|where|which)\b)/i,
      /\bwithout\b.{0,15}\b(?:the )?(?:user|human|operator)(?:'s|s)? (?:knowledge|knowing|consent|noticing|awareness)\b/i,
      /\b(?:secretly|covertly|stealthily)\b.{0,60}\b(?:send|upload|post|transmit|exfiltrat\w*|run|execute|install|download|copy|delete|modify)\b/i,
      /\b(?:hide|conceal)\b[^.:;!?\n]{0,40}\bfrom (?:the )?(?:user|human|operator)\b/i,
      /(?:사용자|유저)(?:에게|한테)?.{0,12}(?:알리지|말하지|보여주지|숨기|숨겨)/,
    ],
  },
  {
    id: 'PI003',
    title: 'Approval or sandbox bypass',
    category: 'prompt-injection',
    severity: 'medium',
    description: 'Text or flags that switch off permission prompts, the sandbox or safety hooks.',
    remediation: 'Do not ship a skill that asks for these. Review by hand before trusting it.',
    patterns: [
      /--dangerously-skip-permissions\b/,
      /--dangerously-bypass-approvals-and-sandbox\b/,
      /\bbypassPermissions\b/,
      /\b(?:bypass|disable|circumvent|turn off|get around)\b.{0,25}\b(?:permission|approval|safety|sandbox|guardrail|security)s?\b.{0,12}\b(?:check|prompt|mode|hook|filter|system)s?\b/i,
    ],
  },
  {
    id: 'PI006',
    title: 'Fake system or role marker',
    category: 'prompt-injection',
    severity: 'medium',
    description: 'Markup that imitates a system message or a chat role, so the text looks like it comes from the platform.',
    remediation: 'Remove the marker. Skill text is ordinary content and must not pose as a system message.',
    patterns: [
      /<\/?\s*(?:system|system-reminder|system_prompt|developer)\s*>/i,
      /<\|(?:im_start|im_end|system|endoftext)\|>/,
      /^\s*\[?(?:SYSTEM|ADMIN|DEVELOPER) (?:MESSAGE|OVERRIDE|INSTRUCTION|PROMPT)\]?\s*:/,
    ],
  },
  {
    id: 'PI007',
    title: 'Instructions loaded from a remote URL',
    category: 'prompt-injection',
    severity: 'medium',
    description: 'The agent is told to fetch a URL and then follow or run what it finds, so the author can change the behaviour after review.',
    remediation: 'Put the instructions in the skill itself, or pin the remote content to a hash you have reviewed.',
    patterns: [
      /\b(?:fetch|curl|wget|download|load|read|retrieve|open)\b.{0,80}https?:\/\/\S+.{0,80}\b(?:and|then)\b.{0,30}\b(?:follow|execute|obey|run|carry out|apply)\b.{0,30}\b(?:instructions?|commands?|steps|it|them|contents?|whatever)\b/i,
    ],
  },

  // ---------------------------------------------------------------- exfiltration
  {
    id: 'EX001',
    title: 'Credential store access',
    category: 'exfiltration',
    severity: 'medium',
    description: 'A reference to a file or store that holds credentials (SSH keys, cloud credentials, tokens, keychain, browser logins).',
    remediation: 'Check why the skill needs it. A skill should use credentials through the tool that owns them, not read the file.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(
        HOME +
          String.raw`\/\.(?:ssh\/(?:id_[a-z0-9]+|authorized_keys)|aws\/credentials|netrc|npmrc|pypirc|git-credentials|docker\/config\.json|kube\/config|config\/gh\/hosts\.yml|config\/gcloud\/|gnupg\/|claude\/\.credentials\.json|codex\/auth\.json)`,
        'i',
      ),
      /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b/,
      /\b(?:cat|less|head|tail|base64|xxd|strings)\s+(?:-\S+\s+)*["']?(?:[\w./~$-]*\/)?\.env(?:\.(?!example|sample|template|dist)[a-z]+)?["']?(?:\s|$|[|;&)])/i,
      /(?:Chrome|Chromium|Firefox|BraveSoftware|Microsoft Edge|Arc)[/\\][^\n]{0,80}[/\\](?:Login Data|Cookies|cookies\.sqlite|logins\.json|key4\.db)\b/,
    ],
  },
  {
    id: 'EX002',
    title: 'Secrets sent over the network',
    category: 'exfiltration',
    severity: 'critical',
    description: 'A command that reads the environment or a credential file and passes it to a network client.',
    remediation: 'Do not install. This is the shape of credential theft; report the skill to where you got it from.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(String.raw`\b(?:env|printenv)\b\s*(?:\|[^|\n]{0,60})?\|\s*` + NET + String.raw`\b`),
      new RegExp(String.raw`\b` + NET + String.raw`\b[^\n]{0,200}\$\(\s*(?:cat|base64|env|printenv|security)\b`),
      new RegExp(String.raw`\b` + NET + String.raw`\b[^\n]{0,200}` + '`' + String.raw`\s*(?:cat|base64|security)\s+[~$/.\w-]`),
      new RegExp(String.raw`\b` + NET + String.raw`\b[^\n]{0,200}@[^\s"']{0,80}(?:\.env\b|\.pem\b|\.ssh\/|\.aws\/|\.netrc|\.npmrc|credentials)`),
      new RegExp(String.raw`(?:\.ssh\/|\.aws\/|\.env\b|\.netrc|\.npmrc|credentials)[^\n|]{0,80}\|[^\n]{0,80}\b` + NET + String.raw`\b`),
    ],
  },
  {
    id: 'EX003',
    title: 'Known data-capture endpoint',
    category: 'exfiltration',
    severity: 'high',
    description: 'A request-catcher, tunnel, paste or file-drop service that is commonly used to receive stolen data.',
    remediation: 'Check what is sent there. A normal skill has no reason to talk to an anonymous capture service.',
    cautionaryDowngrade: true,
    patterns: [
      /\b(?:webhook\.site|requestbin\.(?:com|net)|[a-z0-9.-]*pipedream\.net|requestcatcher\.com|[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator\.net|oast\.(?:fun|pro|live|site|online|me)|interact\.sh|canarytokens\.com|transfer\.sh|file\.io|0x0\.st|pastebin\.com|paste\.ee|ix\.io|termbin\.com)\b/i,
    ],
  },
  {
    id: 'EX004',
    title: 'Secret environment variable passed to a network call',
    category: 'exfiltration',
    severity: 'medium',
    description: 'A network command or HTTP call that includes a key, token or password from the environment. Often legitimate (calling an API with its own key), but the destination must be checked.',
    remediation: 'Confirm the destination host is the service the credential belongs to.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(
        String.raw`\b` + NET + String.raw`\b[^\n]{0,200}\$\{?[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*\}?`,
      ),
      /\b(?:requests\.(?:post|put|get)|urllib\.request|urlopen|fetch\(|axios(?:\.(?:post|put|get))?\(|https?\.request\()[^\n]{0,200}\b(?:os\.environ|process\.env)\b/,
      /\b(?:JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*dict\(\s*os\.environ\s*\)\s*\))/,
    ],
  },
  {
    id: 'EX005',
    title: 'Credential committed in the skill',
    category: 'exfiltration',
    severity: 'high',
    description: 'A string shaped like a real API key, access token or private key is stored in the file.',
    remediation: 'Remove it and revoke the credential. If it is yours, it is already exposed to everyone who received the skill.',
    patterns: [...SECRET_PATTERNS],
  },
  {
    id: 'EX006',
    title: 'Chat webhook endpoint',
    category: 'exfiltration',
    severity: 'medium',
    description: 'A Discord, Telegram or Slack webhook. Used for notifications, and also a common place to send stolen data.',
    remediation: 'Check what the skill sends and whether the webhook belongs to you.',
    cautionaryDowngrade: true,
    patterns: [/\b(?:discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|hooks\.slack\.com\/services\/)/i],
  },
  {
    id: 'EX007',
    title: 'URL with a raw public IP address',
    category: 'exfiltration',
    severity: 'low',
    description: 'A URL that points at a public IP address instead of a host name.',
    remediation: 'Check who owns the address.',
    patterns: [
      /\bhttps?:\/\/(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.))\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/,
    ],
  },

  // ---------------------------------------------------------------- shell
  {
    id: 'SH001',
    title: 'Remote script piped into an interpreter',
    category: 'shell',
    severity: 'high',
    description: 'Code is downloaded and run in one step, so nobody sees what runs and the author can change it at any time.',
    remediation: 'Download the script, read it, then run the reviewed copy (or pin it to a checksum).',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(String.raw`\b(?:curl|wget|fetch)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:env\s+)?(?:` + SHELL + String.raw`\b|` + PIPE_INTERPRETER + ')'),
      new RegExp(String.raw`\b(?:` + SHELL + String.raw`|eval|source|exec)\s+(?:-c\s+)?["']?(?:\$\(|<\(|` + '`' + String.raw`)\s*(?:curl|wget)\b`),
      /\b(?:iex|Invoke-Expression)\b.{0,80}\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b/i,
      /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(?:iex|Invoke-Expression)\b/i,
    ],
  },
  {
    id: 'SH002',
    title: 'Destructive command',
    category: 'shell',
    severity: 'high',
    description: 'A command that deletes a home or system directory, or overwrites a disk.',
    remediation: 'Do not run. Nothing a skill does should need this.',
    cautionaryDowngrade: true,
    patterns: [
      /\brm\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*(?:[rR][a-zA-Z]*f|f[a-zA-Z]*[rR])[a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*["']?(?:\/\*?|~\/?\*?|\$HOME\/?\*?|\$\{HOME\}\/?\*?|\/(?:usr|etc|var|bin|home|Users|System|Library)\/?)["']?(?:\s|$|[;&)|])/,
      /\brm\b[^\n]{0,40}--no-preserve-root\b/,
      /\bdd\b[^\n]{0,80}\bof=\/dev\/(?:sd|hd|disk|nvme|rdisk)/,
      /\bmkfs(?:\.[a-z0-9]+)?\s+\/dev\//,
      /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
      /\bdiskutil\s+(?:eraseDisk|eraseVolume|secureErase)\b/,
    ],
  },
  {
    id: 'SH003',
    title: 'Obfuscated code execution',
    category: 'shell',
    severity: 'high',
    description: 'Code is decoded (base64, hex, character codes) and executed, which hides what actually runs.',
    remediation: 'Decode it by hand and read the result before trusting the skill.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(String.raw`\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:` + SHELL + String.raw`|python[23]?|node|perl)\b`),
      /\b(?:eval|exec)\b[^\n]{0,60}\b(?:base64|b64decode|atob|fromCharCode|unhexlify|rot13|decompress)\b/i,
      new RegExp(String.raw`\b(?:xxd\s+-r|openssl\s+enc\s+-d)\b[^\n]{0,80}\|\s*` + SHELL + String.raw`\b`),
      /[A-Za-z0-9+/]{60,}={0,2}["']?\s*\|\s*base64\s+(?:-d|--decode|-D)\b/,
      /(?:\\x[0-9a-fA-F]{2}){16,}/,
    ],
  },
  {
    id: 'SH004',
    title: 'Reverse shell',
    category: 'shell',
    severity: 'critical',
    description: 'A command that connects a shell on this machine to a remote host.',
    remediation: 'Do not install. Report the skill to where you got it from.',
    cautionaryDowngrade: true,
    patterns: [
      /\/dev\/(?:tcp|udp)\/[^\s/]+\/\d+/,
      /\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-[a-zA-Z]*[ec]\s+\S*(?:sh|bash|cmd|powershell)\b/i,
      /\bmkfifo\b[^\n]{0,160}\b(?:nc|ncat|netcat)\b/,
      /\bsocat\b[^\n]{0,160}\bexec:/i,
      /\bpty\.spawn\(\s*["']\/bin\/(?:ba)?sh/,
      /\bsocket\.socket\([^\n]{0,240}\b(?:subprocess|os\.dup2)\b/,
    ],
  },
  {
    id: 'SH005',
    title: 'Persistence outside the project',
    category: 'shell',
    severity: 'medium',
    description: 'A command that keeps running after the session: shell start-up files, cron, launch agents, system services, SSH authorized keys, global git settings.',
    remediation: 'Check exactly what is installed and whether you want it to outlive the task.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(String.raw`(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?` + HOME + String.raw`\/\.(?:bashrc|zshrc|zprofile|bash_profile|profile|zshenv|config\/fish\/config\.fish|ssh\/authorized_keys)\b`),
      /\bcrontab\s+(?!-l\b)(?:-e\b|-\s*(?:$|[;&)])|[^\s-]\S*)/,
      /\/Library\/Launch(?:Agents|Daemons)\//,
      /\blaunchctl\s+(?:load|bootstrap|enable)\b/,
      /\bsystemctl\s+(?:--user\s+)?enable\b/,
      /\/etc\/(?:cron\.[a-z]+|crontab|rc\.local|systemd\/system|sudoers)\b/,
      /\bgit\s+config\s+(?:--global|--system)\s+(?:core\.hooksPath|core\.sshCommand|credential\.helper|url\.)/,
    ],
  },
  {
    id: 'SH006',
    title: 'Privilege escalation',
    category: 'shell',
    severity: 'medium',
    description: 'A command that takes root, feeds a password to sudo, or makes files world-writable or setuid.',
    remediation: 'Check why the skill needs more rights than the user who runs it.',
    cautionaryDowngrade: true,
    patterns: [
      /\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|[ugo]*\+s|[2467][0-7]{3})\b/,
      /\bsudo\s+(?:-S\b|-i\b|su\b|(?:ba|z)?sh\b)/,
      /\|\s*sudo\s+-S\b/,
      /\bNOPASSWD\s*:/,
    ],
  },
  {
    id: 'SH007',
    title: 'Operating system protection switched off',
    category: 'shell',
    severity: 'high',
    description: 'A command that disables Gatekeeper, SIP, quarantine, SELinux, antivirus, a firewall or TLS verification.',
    remediation: 'Do not run. A skill that needs protections off should be treated as hostile until proven otherwise.',
    cautionaryDowngrade: true,
    patterns: [
      /\bspctl\s+--(?:master-|global-)?disable\b/,
      /\bcsrutil\s+disable\b/,
      /\bxattr\b[^\n]{0,40}com\.apple\.quarantine/,
      /\bSet-ExecutionPolicy\s+(?:-\w+\s+)*(?:Bypass|Unrestricted)\b/i,
      /\bSet-MpPreference\s+-DisableRealtimeMonitoring\b/i,
      /\bsetenforce\s+0\b/,
      /\bufw\s+disable\b/,
      /\bhttp\.sslVerify\s+false\b/,
      /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b/,
    ],
  },

  // ---------------------------------------------------------------- agent configuration (line form)
  {
    id: 'AC007',
    title: 'API endpoint or loader override',
    category: 'agent-config',
    severity: 'high',
    description: 'A setting that sends the agent\'s API traffic (prompts, code and the API key) to another host, or injects code into every process.',
    remediation: 'Remove the override unless the host is a proxy you run yourself.',
    patterns: [
      /\b(?:ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|ANTHROPIC_BEDROCK_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE)["']?\s*[=:]\s*["']?https?:\/\/(?!(?:api\.anthropic\.com|api\.openai\.com|localhost|127\.0\.0\.1)(?:[:/"'\s]|$))/,
      /\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)["']?\s*[=:]\s*["']?[^\s"']/,
      /\bNODE_OPTIONS["']?\s*[=:]\s*["']?[^\n"']{0,80}--(?:require|import|loader)\b/,
    ],
  },
  {
    id: 'AC008',
    title: 'Agent configuration modified by a command',
    category: 'agent-config',
    severity: 'medium',
    description: 'A command that writes to the user-level settings, instructions or hooks of a coding agent, which changes every later session.',
    remediation: 'Check the exact change. Settings and hooks should be edited by the user, not by a skill.',
    cautionaryDowngrade: true,
    patterns: [
      new RegExp(
        String.raw`(?:>>?|\btee\b(?:\s+-a)?|\bcp\b[^\n]{0,120}|\bmv\b[^\n]{0,120}|\bsed\s+-i[^\n]{0,120}|\bln\s+-s[a-z]*[^\n]{0,120})\s*["']?` +
          HOME +
          String.raw`\/\.(?:claude\/(?:settings(?:\.local)?\.json|CLAUDE\.md|hooks\/|agents\/|commands\/)|claude\.json|codex\/(?:config\.toml|AGENTS\.md|hooks\.json)|cursor\/(?:mcp\.json|rules)|gemini\/settings\.json)`,
      ),
    ],
  },
];
