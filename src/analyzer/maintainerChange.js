import { fetchMetadata } from "./registry.js";
import semver from "semver";

function publisherOf(versionDoc) {
  const np = versionDoc?._npmUser;
  if (np?.name) return np.name;
  const m = versionDoc?.maintainers || [];
  return m.map((x) => x?.name).filter(Boolean).sort().join(",");
}

export async function checkMaintainerChange(name, currentVersion) {
  const meta = await fetchMetadata(name);
  if (!meta || !meta.versions || !currentVersion) return [];

  const all = Object.keys(meta.versions);
  let prev = null;
  try {
    const sorted = all.filter((v) => semver.valid(v)).sort(semver.compare);
    const idx = sorted.indexOf(currentVersion);
    if (idx > 0) prev = sorted[idx - 1];
  } catch {
    return [];
  }
  if (!prev) return [];

  const cur = publisherOf(meta.versions[currentVersion]);
  const old = publisherOf(meta.versions[prev]);
  if (!cur || !old) return [];
  if (cur === old) return [];

  return [
    {
      kind: "maintainer-change",
      msg: `公開者が変更されています: ${prev} (${old}) → ${currentVersion} (${cur})`,
      weight: 6,
      severity: "high",
      previousVersion: prev,
      previousPublisher: old,
      currentPublisher: cur,
    },
  ];
}
