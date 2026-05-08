# @osspect/npmguard

`npm install` のサプライチェーン攻撃を **多層防御** で止めるツールセット。**レジストリプロキシ** に加え、**OS サンドボックス + 静的解析 + ロックファイル監査 + レピュテーション + 動作差分 + 分散脅威インテリジェンス** を備えます。

> パッケージ名: `@osspect/npmguard` ／ CLI 名: `npm-guard`
> 対応: macOS (sandbox-exec) / Linux (firejail) / Windows（best-effort）／ Node 18.17+

## インストール

```bash
npm install -g @osspect/npmguard
```

ローカル開発:

```bash
cd "/Users/ktoshi/Documents/npm guard"
npm install
npm link
```

## 2 つの動作モード

### モード A — Drop-in `npm install` 置き換え（推奨）

`npm install` の代わりに `npm-guard install` を使うだけ。

```bash
npm-guard install lodash
npm-guard i react react-dom        # `i` は alias
npm-guard install --scan           # 深いスキャン込み
npm-guard install --json           # CI 向け
npm-guard install --dry-run        # 実行せず予測のみ
npm-guard install --loose          # サンドボックスのファイル制限を外す
npm-guard install --no-report      # 匿名シグナルを送らない
```

何が起きるか:

1. **事前スキャン** — タイポスクワット / 既知マルウェア / 直近公開 / メンテナ単独 / 低 DL を判定。`block` 判定は **インストール前に拒否**。
2. **`npm install --ignore-scripts`** で素のインストール。
3. 全パッケージの `preinstall` / `install` / `postinstall` を **OS サンドボックスで実行**（macOS: sandbox-exec、Linux: firejail）。ネットワーク遮断＋ファイルアクセス制限。
4. **動作差分** — 前回スナップショットと比較してスクリプトの変化を検知。
5. **`--scan`** で更にロックファイル監査・レピュテーション集計・タイポスクワット網羅検査。
6. **脅威インテル** クエリ（設定済みの場合）。
7. すべて `~/.npm-guard/audit.log` に JSONL で記録。

### モード B — レジストリプロキシ（Takumi 同等）

メタデータレベルで `403` を返す。すべての `npm` 操作が透過的にガードされる。

```bash
npm-guard start                # プロキシ起動 (127.0.0.1:7878)
npm-guard npmrc-install        # ~/.npmrc を切替
npm install <whatever>         # 通常通り。危険物は 403
npm-guard npmrc-uninstall      # 戻す
```

## コマンド一覧

| コマンド | 用途 |
|---|---|
| `install` / `i` | safenpm 互換 drop-in 置き換え |
| `doctor` | プロジェクトの健全性レポート（A+〜F） |
| `fix` | タイポスクワットの自動置換 |
| `diff` | 前回スナップショットからの変更差分 |
| `diff --snapshot` | スナップショット作成 |
| `audit` | 監査ログ（直近の判定）を表示 |
| `scan <pkg>` | 単独パッケージスキャン |
| `start` | レジストリプロキシ起動 |
| `npmrc-install` / `npmrc-uninstall` | プロキシへの切替 |
| `allow <pkg>` / `disallow` / `allowlist` | グローバル許可リスト |
| `update` | 既知侵害パッケージリストを最新化 |
| `blocklist-info` | 適用中ブロックリストのメタ情報 |
| `intel set <url>` / `enable` / `disable` | 脅威インテリ設定 |

### `--interactive`（プロンプト承認）

`npm-guard install -I lodash react reacct` のように使うと、`block`/`ask` 判定のたびに `skip / abort / allow` を対話的に選べます。`allow` を選べばその場でグローバル許可リストに追加して続行します。

## 検査内容

### 静的解析（19 ルール）

| 重み | 例 |
|---|---|
| **High (30)** | `curl\|sh` パイプ実行 / `curl/wget` / Windows 系ダウンローダ / `require('https')` / `fetch()` / DNS 解決 / 認証情報 (`process.env.NPM_TOKEN`, `~/.ssh`, `.aws/credentials`, `.npmrc`, `.netrc`) / `eval` / `base64` |
| **Medium (15)** | `/etc/passwd` / 子プロセス / 16進・Unicode 難読化 / Raw socket (`net`/`dgram`) / `$HOME` |
| **Low (5)** | `node-gyp` / `prebuild-install` / `node-pre-gyp` |

スコアは 100 でキャップ。`critical (60+)` `suspicious (30-59)` `low (1-29)` `clean (0)`。

### タイポスクワット 5 検出器

1. Levenshtein 距離 ≤ 2
2. 文字置換 (`0→o`, `1→l`, `rn→m` 等)
3. 隣接文字入れ替え (`axois → axios`)
4. 1 文字省略 / 余分（双方向）
5. スコープ混乱 (`@evil/lodash` ↔ `lodash`)
6. 接尾辞攻撃 (`lodash-helper`, `lodash-utils`, ...)

### ロックファイル監査

- lockfile 欠落・破損
- git 依存 / file:依存 / 平文 HTTP
- integrity 欠落 / sha1・md5 等の弱いハッシュ
- 公式以外のレジストリ
- `package.json` より古い lockfile

### レピュテーション 0–100

メンテナ数・ライセンス・リポジトリ・description・成熟度・依存数・スクリプト有無・週間 DL を加減点。

### メンテナ変更検出

`semver` で前バージョンを特定し、`_npmUser` / maintainers の差分を検出（アカウント乗っ取りシグナル）。

### 動作差分（Behavioral Diff）

各プロジェクト直下 `.npmguard-snapshot/` にライフサイクルスクリプトをハッシュで記録。`npm update` 後の `diff` で何が変わったか追跡。

### 既知の脅威（OSV.dev）

公開アドバイザリ（`MAL-*` / `GHSA-*`）と一致する場合に severity 重み（critical 8 / high 6 / medium 4 / low 2）。

### 既知の侵害パッケージリスト（Shai-Hulud feed）

`src/data/compromised.txt` に **1,700+ 件の確定侵害バージョン**を同梱（[Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) ベース）。

- 完全一致 (`name@version`) → **即時ブロック** (score 100)
- 名前のみ一致（別バージョンが侵害） → 警告 (score 8)＋ ask
- 最新リスト取得: `npm-guard update`
- リストの状態確認: `npm-guard blocklist-info`

`~/.npm-guard/compromised.txt` に保存され、bundled より優先されます。

## Doctor — プロジェクト健全性

```bash
npm-guard doctor
# grade: A  score: 92/100
#   lockfile     95/100 (weight 20%)
#   scripts     100/100 (weight 25%)
#   typosquats  100/100 (weight 20%)
#   reputation   78/100 (weight 15%)
#   behavior    100/100 (weight 10%)
#   hygiene      85/100 (weight 10%)
```

スコア < 70 で exit 1、< 60 で exit 2（CI ゲート用）。

## サンドボックス

| OS | 実装 | ネットワーク遮断 | ファイル制限 |
|---|---|---|---|
| macOS | `sandbox-exec` (内蔵) | ✅ | ✅ |
| Linux | `firejail` (`apt install firejail`) | ✅ | ✅ |
| Windows | best-effort | ❌ | ❌（`--loose` 必須） |

`bcrypt` / `sharp` / `node-gyp` のような **正当な install スクリプト** は `.npmguardrc` に登録すれば素通し。

## `.npmguardrc`

プロジェクトルートまたは `~/.npmguardrc`:

```
# コメント
bcrypt
sharp
@img/*
@mycompany/*
```

スコープ単位のワイルドカードに対応。

## 環境変数

| 変数 | 用途 | 既定 |
|---|---|---|
| `NPM_GUARD_HOME` | データディレクトリ | `~/.npm-guard` |
| `NPM_GUARD_UPSTREAM` | 上流レジストリ | `https://registry.npmjs.org` |
| `NPM_GUARD_PORT` | プロキシポート | `7878` |
| `NPM_GUARD_HOST` | プロキシホスト | `127.0.0.1` |
| `NPM_GUARD_INTEL_URL` | 脅威インテル URL | (未設定) |
| `NPM_GUARD_NO_REPORT` | `1` で送信無効 | (未設定) |
| `NPM_GUARD_DEBUG` | 詳細ログ | (未設定) |

## 脅威インテリジェンスネットワーク

匿名シグナルを集約する分散ネットワークの **クライアント** が組み込まれています。サーバ側仕様（API スキーマ・SQL・匿名性保証・反スパム・Cloudflare Workers サンプル）は **[SPEC.md](./SPEC.md)** を参照してください。

クライアント設定:

```bash
npm-guard intel set https://intel.example.com
npm-guard intel disable        # 送信停止（クエリは継続）
```

匿名性:

- 送信内容は `package` / `version` / `script_hash` / `category` / `severity` のみ
- IP・ホスト名・パス・UA を一切送らない
- `reporter_id` は **日次でローテーションするハッシュ**（同一ユーザー追跡不可）

## CI / GitHub Actions

```yaml
- name: Install with npm-guard
  run: |
    npm install -g @osspect/npmguard
    npm-guard install --json --scan --no-report > report.json

- name: Fail on blocks
  run: |
    BLOCKED=$(jq '.summary.blocked' report.json)
    TYPOS=$(jq '.summary.typosquats' report.json)
    if [ "$BLOCKED" -gt 0 ] || [ "$TYPOS" -gt 0 ]; then
      exit 1
    fi

- name: Health gate
  run: npm-guard doctor --json     # exit 2 on D/F, 1 on C-, 0 otherwise
```

## ファイル配置

```
~/.npm-guard/
├── allowlist.json       # グローバル許可
├── config.json          # ユーザー設定 (intelBaseUrl など)
├── events.log           # プロキシ判定ログ
└── audit.log            # コマンド実行監査ログ（5MB で 3 世代ローテーション）

<project>/
├── .npmguardrc          # プロジェクト許可
└── .npmguard-snapshot/  # 動作差分用ベースライン
```

## 仕組み（プロキシモード）

```
┌──────────┐    ① GET /<pkg>            ┌────────────┐
│   npm    │ ─────────────────────────▶ │ npm-guard  │
└──────────┘ ◀─── ② JSON or 403 ─────── │   :7878    │
                                         └─────┬──────┘
                       ③ メタデータ取得         ▼
                                       https://registry.npmjs.org
                       ④ tarball は 302 redirect
```

## 仕組み（drop-in モード）

```
   npm-guard install ▶  ① pre-scan
                        ② npm install --ignore-scripts
                        ③ for pkg in node_modules:
                             - sandbox-exec / firejail でフックを実行
                             - 違反は記録 + 匿名シグナル送信
                        ④ behavioral diff vs last snapshot
                        ⑤ optional: deep scan / intel query
                        ⑥ ~/.npm-guard/audit.log に JSONL 追記
```

## 制限事項

- pnpm / yarn 未対応（npm のみ）
- 認証付き private registry 未対応
- Windows 環境では kernel-level サンドボックスを提供できないため `--loose` 必須
- OSV.dev / npm registry 障害時は **fail-open**（pass-through）

## ライセンス

**Use-Only License**（使用のみ許可）。詳細は [LICENSE](./LICENSE) を参照してください。

要点（参考）:

- ✅ 自分の管理下のシステムへの **インストール・実行** は OK
- ❌ 改変・派生物の作成 / 再配布・販売・サブライセンス
- ❌ SaaS など第三者へのサービス提供
- ❌ 競合製品の開発のための利用
- ❌ リバースエンジニアリング（法令で許容される場合を除く）
- 第三者 OSS 依存（commander / kleur / lru-cache / semver / Shai-Hulud feed 等）はそれぞれのライセンスに従います
