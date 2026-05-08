import { FRESHNESS_DAYS } from "../config.js";

export function checkFreshness(meta, version) {
  const t = meta?.time?.[version];
  if (!t) return [];

  const ageMs = Date.now() - new Date(t).getTime();
  const ageDays = ageMs / 86400000;
  if (ageDays >= FRESHNESS_DAYS) return [];

  let weight;
  if (ageDays < 1) weight = 5;
  else if (ageDays < 3) weight = 4;
  else if (ageDays < 7) weight = 3;
  else weight = 2;

  return [
    {
      kind: "freshness",
      msg: `公開から ${ageDays.toFixed(1)} 日（${FRESHNESS_DAYS}日未満は警戒対象）`,
      weight,
      ageDays,
    },
  ];
}
