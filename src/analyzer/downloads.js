import { fetchDownloads } from "./registry.js";

export async function checkDownloads(name) {
  const data = await fetchDownloads(name);
  if (!data) return [];

  const dls = data.downloads ?? 0;
  const findings = [];

  if (dls < 50) {
    findings.push({
      kind: "downloads:rare",
      msg: `週間DL ${dls} 件（極端に少ない）`,
      weight: 3,
      downloads: dls,
    });
  } else if (dls < 500) {
    findings.push({
      kind: "downloads:low",
      msg: `週間DL ${dls} 件（やや少ない）`,
      weight: 1,
      downloads: dls,
    });
  }

  return findings;
}
