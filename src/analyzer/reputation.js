import { fetchMetadata, fetchDownloads } from "./registry.js";

const HALF_YEAR = 1000 * 60 * 60 * 24 * 30 * 6;

export async function reputationOf(name, version) {
  const meta = await fetchMetadata(name);
  if (!meta) return { name, version, score: 50, factors: [{ msg: "メタデータ取得不可", weight: 0 }] };

  const v = version || meta["dist-tags"]?.latest;
  const versionDoc = meta?.versions?.[v];
  const factors = [];
  let score = 100;

  // Maintainers
  const maintainers = versionDoc?.maintainers || meta?.maintainers || [];
  if (maintainers.length === 0) {
    score -= 20;
    factors.push({ msg: "メンテナ情報なし", weight: -20 });
  } else if (maintainers.length === 1) {
    score -= 10;
    factors.push({ msg: "メンテナが 1 名のみ", weight: -10 });
  } else {
    factors.push({ msg: `メンテナ ${maintainers.length} 名`, weight: 0 });
  }

  // License
  const license = versionDoc?.license || meta?.license || null;
  if (!license) {
    score -= 10;
    factors.push({ msg: "ライセンス未設定", weight: -10 });
  }

  // Repository
  const repo = versionDoc?.repository || meta?.repository;
  if (!repo) {
    score -= 10;
    factors.push({ msg: "リポジトリ情報なし", weight: -10 });
  }

  // Description
  if (!versionDoc?.description && !meta?.description) {
    score -= 5;
    factors.push({ msg: "description が無い", weight: -5 });
  }

  // Maturity (first publish vs latest)
  const time = meta?.time || {};
  const created = time.created ? new Date(time.created).getTime() : 0;
  const ageMs = created ? Date.now() - created : 0;
  if (ageMs > 0 && ageMs < HALF_YEAR) {
    score -= 10;
    factors.push({ msg: "公開から半年未満（成熟度低）", weight: -10 });
  } else if (ageMs >= HALF_YEAR) {
    factors.push({ msg: `公開から ${Math.floor(ageMs / (1000 * 60 * 60 * 24))} 日`, weight: 0 });
  }

  // Dependencies count
  const deps = versionDoc?.dependencies ? Object.keys(versionDoc.dependencies).length : 0;
  if (deps > 30) {
    score -= 10;
    factors.push({ msg: `依存が ${deps} 件と多い`, weight: -10 });
  } else if (deps > 15) {
    score -= 5;
    factors.push({ msg: `依存が ${deps} 件`, weight: -5 });
  }

  // Install scripts presence
  const scripts = versionDoc?.scripts || {};
  if (scripts.preinstall || scripts.install || scripts.postinstall) {
    score -= 5;
    factors.push({ msg: "ライフサイクルスクリプトあり", weight: -5 });
  }

  // Downloads (popularity boost)
  try {
    const dl = await fetchDownloads(name);
    const dls = dl?.downloads ?? 0;
    if (dls < 50) {
      score -= 15;
      factors.push({ msg: `週間DL ${dls} 件と極端に少ない`, weight: -15 });
    } else if (dls < 500) {
      score -= 5;
      factors.push({ msg: `週間DL ${dls} 件`, weight: -5 });
    } else if (dls > 100000) {
      score = Math.min(100, score + 5);
      factors.push({ msg: `週間DL ${dls} 件（人気）`, weight: 5 });
    }
  } catch {}

  return { name, version: v, score: Math.max(0, Math.min(100, score)), factors };
}

export function aggregateReputation(scores) {
  if (!scores.length) return { overallScore: 0, count: 0 };
  const sum = scores.reduce((s, x) => s + x.score, 0);
  const overallScore = Math.round(sum / scores.length);
  return { overallScore, count: scores.length };
}
