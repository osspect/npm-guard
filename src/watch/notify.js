import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { appendEvent } from "../util/log.js";

const execFileAsync = promisify(execFile);

export async function notifyWatchAlerts({
  projectLabel,
  cwd,
  alerts,
}) {
  if (!alerts.length) return;

  const title = "npm-guard: 依存パッケージのリスクが上昇しました";
  const lines = alerts.map((a) => a.summary).slice(0, 12);
  let body = `${projectLabel}\n${lines.join("\n")}`;
  if (alerts.length > 12) body += `\n…他 ${alerts.length - 12} 件`;

  await appendEvent({
    type: "watch-alert",
    cwd,
    projectLabel,
    count: alerts.length,
    packages: alerts.map((a) => ({ id: a.id, summary: a.summary })),
  });

  const webhook = process.env.NPM_GUARD_WATCH_WEBHOOK_URL;
  if (webhook) {
    try {
      await fetch(webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          source: "npm-guard",
          event: "watch-alert",
          projectLabel,
          cwd,
          alerts,
          ts: new Date().toISOString(),
        }),
      });
    } catch {
      /* ignore */
    }
  }

  if (process.env.NPM_GUARD_WATCH_NO_DESKTOP === "1") return;

  try {
    if (process.platform === "darwin") {
      await execFileAsync("osascript", [
        "-e",
        `display notification ${JSON.stringify(body)} with title ${JSON.stringify(title)}`,
      ]);
    } else if (process.platform === "linux") {
      await execFileAsync("notify-send", [
        "-a",
        "npm-guard",
        title,
        body.slice(0, 500),
      ]);
    }
  } catch {
    /* optional */
  }
}
