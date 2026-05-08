export function parseSpec(spec) {
  if (!spec || typeof spec !== "string") {
    return { name: "", version: undefined };
  }
  if (spec.startsWith("@")) {
    const idx = spec.indexOf("@", 1);
    if (idx > 0) {
      return { name: spec.slice(0, idx), version: spec.slice(idx + 1) || undefined };
    }
    return { name: spec, version: undefined };
  }
  const idx = spec.indexOf("@");
  if (idx > 0) {
    return { name: spec.slice(0, idx), version: spec.slice(idx + 1) || undefined };
  }
  return { name: spec, version: undefined };
}
