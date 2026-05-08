// 19 detection rules across 3 severity tiers (inspired by safenpm).
// Weights are summed and capped at 100 by the analyzer.

const HIGH = 30;
const MED = 15;
const LOW = 5;

export const LIFECYCLE_PATTERNS = [
  // ===== High severity =====
  {
    re: /(^|[\s;|&`(])(curl|wget|fetch)\b[^|]*\|\s*(sh|bash|zsh)/i,
    weight: HIGH,
    msg: "curl/wget で取得したコンテンツをシェルにパイプ実行しています",
    kind: "lifecycle:pipe-to-shell",
    severity: "high",
  },
  {
    re: /(^|[\s;|&`(])(curl|wget|nc|ncat)\b/i,
    weight: HIGH,
    msg: "外部URLを取得するコマンド (curl/wget/nc) が含まれます",
    kind: "lifecycle:network-fetch",
    severity: "high",
  },
  {
    re: /\b(powershell|iwr|Invoke-WebRequest|Invoke-Expression|certutil|bitsadmin)\b/i,
    weight: HIGH,
    msg: "Windows系のダウンロード/実行命令が含まれます",
    kind: "lifecycle:windows-fetch",
    severity: "high",
  },
  {
    re: /require\s*\(\s*['"`](https?|net|tls|dgram)['"`]\s*\)|import\s+[^;]+from\s+['"`](https?|net|tls|dgram)['"`]/,
    weight: HIGH,
    msg: "ネットワークモジュールを直接 require/import しています",
    kind: "lifecycle:net-require",
    severity: "high",
  },
  {
    re: /\bfetch\s*\(\s*['"`]https?:/i,
    weight: HIGH,
    msg: "fetch() で外部URLにアクセスしています",
    kind: "lifecycle:fetch-call",
    severity: "high",
  },
  {
    re: /require\s*\(\s*['"`]dns['"`]\s*\)|\bdns\.(resolve|lookup)/,
    weight: HIGH,
    msg: "DNS 解決を行っています（経路を変えた exfiltration の兆候）",
    kind: "lifecycle:dns-exfil",
    severity: "high",
  },
  {
    re: /process\.env\.(NPM_TOKEN|NODE_AUTH_TOKEN|AWS_(ACCESS_KEY|SECRET)|GITHUB_TOKEN|GH_TOKEN|SSH_|SECRET|API_KEY|PRIVATE_KEY|DATABASE_URL|STRIPE_)/,
    weight: HIGH,
    msg: "認証情報・シークレットを参照しています",
    kind: "lifecycle:secret-read",
    severity: "high",
  },
  {
    re: /(\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)|~\/\.ssh|os\.homedir\(\)[^;]*['"`]\.ssh)/,
    weight: HIGH,
    msg: "~/.ssh 配下のファイルにアクセスしています",
    kind: "lifecycle:ssh-access",
    severity: "high",
  },
  {
    re: /(\.aws\/credentials|\.npmrc|\.netrc|\.docker\/config|\.kube\/config)/,
    weight: HIGH,
    msg: "認証情報を含むドットファイル (.aws/.npmrc/.netrc/.docker/.kube) にアクセスしています",
    kind: "lifecycle:dotfile-access",
    severity: "high",
  },
  {
    re: /\beval\s*\(/,
    weight: HIGH,
    msg: "eval が使用されています",
    kind: "lifecycle:eval",
    severity: "high",
  },
  {
    re: /\b(base64\s+(-d|--decode)|atob\s*\(|Buffer\.from\([^,]+,\s*['"]base64['"])/i,
    weight: HIGH,
    msg: "base64 デコード処理が含まれます",
    kind: "lifecycle:base64",
    severity: "high",
  },

  // ===== Medium severity =====
  {
    re: /\/etc\/passwd|\/etc\/shadow/,
    weight: MED,
    msg: "/etc/passwd や /etc/shadow を読み取っています",
    kind: "lifecycle:passwd-read",
    severity: "medium",
  },
  {
    re: /\b(child_process|execSync|spawnSync|spawn|exec)\s*\(/,
    weight: MED,
    msg: "子プロセス実行が含まれます",
    kind: "lifecycle:child-process",
    severity: "medium",
  },
  {
    re: /(\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode)/i,
    weight: MED,
    msg: "16進/Unicodeエスケープによる難読化が含まれます",
    kind: "lifecycle:obfuscation",
    severity: "medium",
  },
  {
    re: /require\s*\(\s*['"`](net|dgram)['"`]\s*\)/,
    weight: MED,
    msg: "Raw ソケット (net/dgram) を作成しています",
    kind: "lifecycle:raw-socket",
    severity: "medium",
  },
  {
    re: /process\.env\.HOME|os\.homedir\(\)/,
    weight: MED,
    msg: "$HOME へアクセスしています",
    kind: "lifecycle:home-access",
    severity: "medium",
  },

  // ===== Low severity =====
  {
    re: /\bnode-gyp\b/,
    weight: LOW,
    msg: "node-gyp によるネイティブビルドが含まれます",
    kind: "lifecycle:node-gyp",
    severity: "low",
  },
  {
    re: /\bprebuild-install\b/,
    weight: LOW,
    msg: "prebuild-install でプリビルド済みバイナリを取得します",
    kind: "lifecycle:prebuild-install",
    severity: "low",
  },
  {
    re: /\bnode-pre-gyp\b/,
    weight: LOW,
    msg: "node-pre-gyp によるバイナリ取得・ビルドが含まれます",
    kind: "lifecycle:node-pre-gyp",
    severity: "low",
  },
];

export const SEVERITY_TIERS = { HIGH, MED, LOW };
