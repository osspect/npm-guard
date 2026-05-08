export function checkMaintainers(meta, version) {
  const versionDoc = meta?.versions?.[version];
  const m = versionDoc?.maintainers || meta?.maintainers || [];
  const findings = [];

  if (!Array.isArray(m) || m.length === 0) {
    findings.push({
      kind: "maintainers:none",
      msg: "メンテナ情報が取得できません",
      weight: 1,
    });
    return findings;
  }

  if (m.length === 1) {
    findings.push({
      kind: "maintainers:single",
      msg: "メンテナが 1 名のみ",
      weight: 1,
    });
  }

  return findings;
}
