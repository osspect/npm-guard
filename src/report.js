export function renderReport(result) {
  const lines = [];
  const head =
    result.decision === "block"
      ? "[npm-guard] 危険度: 高（ブロック）"
      : result.decision === "ask"
        ? "[npm-guard] 危険度: 中（要承認）"
        : "[npm-guard] 安全";

  lines.push(`${head} (score ${result.score})`);
  lines.push(`- ${result.name}${result.version ? "@" + result.version : ""}`);

  for (const f of result.findings) {
    const w = f.weight ? ` (+${f.weight})` : "";
    lines.push(`  · ${f.msg}${w}`);
  }

  if (result.decision === "ask") {
    lines.push("");
    lines.push("承認するには次のいずれかを実行してください:");
    lines.push(`  npm-guard allow ${result.name}@${result.version}`);
    lines.push("もしくはバージョンを指定せずに名前単位で許可:");
    lines.push(`  npm-guard allow ${result.name}`);
    lines.push("ライフサイクルスクリプトだけを止めて入れる場合:");
    lines.push("  npm install --ignore-scripts <package>");
  } else if (result.decision === "block") {
    lines.push("");
    lines.push("インストールはブロックされました。明示的に許可する場合:");
    lines.push(`  npm-guard allow ${result.name}@${result.version}`);
  }

  return lines.join("\n");
}
