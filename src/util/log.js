import kleur from "kleur";
import fs from "node:fs/promises";
import { EVENTS_LOG, ensureDataDir } from "../config.js";

const isDebug = !!process.env.NPM_GUARD_DEBUG;

export const log = {
  info: (...m) => console.log(...m),
  warn: (...m) => console.warn(kleur.yellow("[warn]"), ...m),
  error: (...m) => console.error(kleur.red("[error]"), ...m),
  ok: (...m) => console.log(kleur.green("[ok]"), ...m),
  blocked: (...m) => console.warn(kleur.red().bold("[BLOCK]"), ...m),
  ask: (...m) => console.warn(kleur.yellow().bold("[ASK]"), ...m),
  allow: (...m) => console.log(kleur.gray("[allow]"), ...m),
  debug: (...m) => isDebug && console.error(kleur.gray("[debug]"), ...m),
};

export async function appendEvent(entry) {
  try {
    await ensureDataDir();
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    await fs.appendFile(EVENTS_LOG, line);
  } catch (e) {
    log.debug("failed to append event:", e?.message);
  }
}
