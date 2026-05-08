# npm-guard 脅威インテリジェンスネットワーク 仕様書

ローカルで検出した悪性パッケージ情報を **匿名で集約** し、別ユーザーが同じパッケージをインストールしようとした際に **事前に警告** する分散ネットワークの仕様。safenpm の "Decentralized Intelligence" と同等。

## 目的

- 一人がブロックした情報で全員を守る
- IP / ユーザー名 / プロジェクト名 / ファイルパスを一切収集しない
- スパム・改ざんを抑える（重複・Sybil 対策）

## システム構成

```
[npm-guard CLI]                          [Intel Server]                  [Web Dashboard]
                                                                         (transparency)
  scan/install ──── POST /v1/signal ───▶  /v1/signal      ┐
                                          (rate-limit)    │
  scan/install ◀─── GET  /v1/check ─────  /v1/check       ├──▶ DB (signals)
                                          /v1/recent      │     ┌──────────────┐
                                          /v1/stats       ┘     │ pkg, version │
                                                                │ script_hash  │
                                                                │ category     │
                                                                │ reporter_id  │
                                                                │ ts           │
                                                                └──────────────┘
```

推奨スタック例: **Cloudflare Workers + D1 / KV** または **Fly.io + SQLite + LiteFS**。月数万シグナル規模なら無料枠で十分。

## エンドポイント

### `POST /v1/signal` — シグナル投稿

リクエスト:

```http
POST /v1/signal HTTP/1.1
Content-Type: application/json
X-Reporter-Id: <sha256(daily-salt)>

{
  "package": "axois",
  "version": "1.0.0",
  "scriptHash": "sha256:abcdef...",
  "category": "typosquat | network-fetch | secret-read | dns-exfil | maintainer-change | malware-osv | other",
  "severity": "low | medium | high | critical",
  "ts": "2026-05-08T08:30:00Z"
}
```

レスポンス:

```json
{ "accepted": true, "id": "sig_01HW..." }
```

### `GET /v1/check?name=&version=` — クエリ

レスポンス:

```json
{
  "package": "axois",
  "version": "1.0.0",
  "flagged": true,
  "reportCount": 12,
  "uniqueReporters": 5,
  "categories": ["typosquat", "network-fetch"],
  "firstSeen": "2026-05-01T...",
  "lastSeen": "2026-05-08T..."
}
```

未フラグ時は `flagged: false` で返す（`reportCount: 0`）。

### `GET /v1/recent?limit=100` — 最近のシグナル（透明性ダッシュボード用）

```json
{
  "items": [
    { "package": "axois", "version": "1.0.0", "category": "typosquat", "severity": "high", "ts": "..." }
  ]
}
```

### `GET /v1/stats` — 集計

```json
{
  "since": "2026-04-08",
  "totalSignals": 18342,
  "flaggedPackages": 87,
  "topCategories": [
    { "category": "typosquat", "count": 6210 },
    { "category": "network-fetch", "count": 5102 }
  ]
}
```

## データモデル

```sql
CREATE TABLE signals (
  id            TEXT PRIMARY KEY,           -- ULID
  package       TEXT NOT NULL,
  version       TEXT,
  script_hash   TEXT,
  category      TEXT NOT NULL,
  severity      TEXT NOT NULL,
  reporter_id   TEXT NOT NULL,              -- daily-rotated hash
  ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_signals_pkg_ver ON signals (package, version);
CREATE INDEX idx_signals_ts ON signals (ts);
```

集計マテビュー（または都度集計）:

```sql
CREATE MATERIALIZED VIEW pkg_flags AS
SELECT
  package,
  version,
  COUNT(*)                              AS report_count,
  COUNT(DISTINCT reporter_id)           AS unique_reporters,
  array_agg(DISTINCT category)          AS categories,
  MIN(ts) AS first_seen,
  MAX(ts) AS last_seen
FROM signals
WHERE ts > now() - INTERVAL '90 days'
GROUP BY package, version;
```

## 匿名性保証

| 項目 | 仕様 |
|---|---|
| **送信側に含めない** | IP、ホスト名、ユーザー名、プロジェクトパス、絶対パス、UA |
| **`reporter_id`** | `SHA256("npmguard-" + UTC日付)` で当日内のみ識別。日付が変われば別人扱い |
| **クライアント IP** | サーバ側でも保持しない（`anonymizeIp` ミドルウェアで `0.0.0.0/16` に切り捨て、ログには出さない） |
| **保持期間** | 90 日（経過後は集計値のみ残す） |
| **送信内容の範囲** | `package` / `version` / `scriptHash` / `category` / `severity` のみ |

## 反スパム / Sybil 対策

1. **レート制限**: `reporter_id` あたり 100 件/時、IP あたり 1000 件/時（IP は破棄して再構築困難）
2. **重複排除**: `(reporter_id, package, version, script_hash)` の組合せで 1 日 1 件
3. **しきい値フラグ付け**:
   - 一般パッケージ … `unique_reporters >= 3`
   - 人気パッケージ（週間DL > 100k）… `unique_reporters >= 15`
4. **スクリプトハッシュ整合性**: 同じ `(package, version)` で `script_hash` が合致しないシグナルは集計から除外（人気パッケージへの濡れ衣攻撃防止）
5. **既知の良性パッケージ**: lodash / express / react など事前にホワイトリスト化、フラグ付けするには `unique_reporters >= 50` 必要

## オプトアウト

- クライアント側 `--no-report`、または `~/.npm-guard/config.json` の `"intelReporting": false`
- オプトアウト中も **クエリは可能**（情報の片務取得は許可）

## サーバ実装サンプル（Cloudflare Workers）

```ts
// worker.ts
import { Router } from "itty-router";
import { ulid } from "ulid";

const router = Router();

router.post("/v1/signal", async (req, env) => {
  const reporter = req.headers.get("x-reporter-id") || "";
  if (!/^[a-f0-9]{32}$/.test(reporter)) return new Response("bad reporter", { status: 400 });
  const body = await req.json();
  const { package: pkg, version, scriptHash, category, severity } = body;
  if (!pkg || !category || !severity) return new Response("missing fields", { status: 400 });

  const id = ulid();
  await env.DB.prepare(
    `INSERT INTO signals (id, package, version, script_hash, category, severity, reporter_id) VALUES (?,?,?,?,?,?,?)
     ON CONFLICT (reporter_id, package, version, script_hash) DO NOTHING`,
  )
    .bind(id, pkg, version || null, scriptHash || null, category, severity, reporter)
    .run();
  return Response.json({ accepted: true, id });
});

router.get("/v1/check", async (req, env) => {
  const url = new URL(req.url);
  const name = url.searchParams.get("name");
  const version = url.searchParams.get("version") || "";
  const row = await env.DB.prepare(
    `SELECT COUNT(*) as report_count, COUNT(DISTINCT reporter_id) as unique_reporters,
            MIN(ts) as first_seen, MAX(ts) as last_seen
       FROM signals WHERE package = ? AND (? = '' OR version = ?)`,
  ).bind(name, version, version).first();

  const popular = await isPopular(name, env);
  const threshold = popular ? 15 : 3;
  const flagged = (row?.unique_reporters ?? 0) >= threshold;
  return Response.json({
    package: name,
    version,
    flagged,
    reportCount: row.report_count ?? 0,
    uniqueReporters: row.unique_reporters ?? 0,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
  });
});

export default { fetch: (req, env) => router.handle(req, env) };
```

スキーマ:

```sql
CREATE TABLE signals (
  id           TEXT PRIMARY KEY,
  package      TEXT NOT NULL,
  version      TEXT,
  script_hash  TEXT,
  category     TEXT NOT NULL,
  severity     TEXT NOT NULL,
  reporter_id  TEXT NOT NULL,
  ts           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (reporter_id, package, version, script_hash)
);
CREATE INDEX idx_pkg_ver ON signals (package, version);
```

## Web ダッシュボード（オプション）

透明性のために **公開ページ** を用意するのが推奨。表示要素:

- 累計シグナル数 / フラグ済パッケージ数
- 最近 100 件のシグナル（package / category / severity / 時刻）
- カテゴリ別バー
- ネットワーク稼働状況（API レスポンスタイム）

技術: 静的 HTML + `GET /v1/recent` `GET /v1/stats` を fetch して描画。Pages / Vercel / Netlify 等で配信。

## クライアント設定

`~/.npm-guard/config.json`:

```json
{
  "intelBaseUrl": "https://intel.example.com",
  "intelReporting": true
}
```

CLI から:

```bash
npm-guard intel set https://intel.example.com   # サーバ URL を設定
npm-guard intel disable                         # 送信を停止（クエリは継続）
npm-guard intel enable
```

## デプロイ手順（最小例）

1. Cloudflare Workers + D1
2. `wrangler init`、上記 SQL でテーブル作成
3. `wrangler deploy`
4. `npm-guard intel set https://<your-worker>.workers.dev`

## 法的・倫理的留意点

- **GDPR / 改正個人情報保護法**: 送信内容に個人を識別できる情報を含めないため、原則として個人データに該当しない設計
- **悪意のあるパッケージ作者からの DMCA / 訴訟リスク**: 公的な脆弱性 ID（OSV / GHSA）に紐づくものを優先表示するなどで防御
- **ホワイトリスト** で誤検出時の影響を抑制
