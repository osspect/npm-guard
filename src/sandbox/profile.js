// macOS sandbox-exec profile (sbpl/scheme-like syntax).
// Allow basic file IO inside project + npm cache, deny network entirely.
export function macosProfile({ allowPaths = [], cwd } = {}) {
  const paths = [cwd, ...allowPaths]
    .filter(Boolean)
    .map((p) => `(subpath "${p.replace(/"/g, "")}")`)
    .join(" ");

  return `(version 1)
(deny default)
(allow process-fork)
(allow process-exec)
(allow signal (target self))
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix-shm)
(allow file-read*)
(allow file-write*
  ${paths}
)
(deny network*)
`;
}

// firejail flags for Linux network/filesystem isolation.
export function firejailArgs({ cwd, allowPaths = [] } = {}) {
  const args = [
    "--quiet",
    "--noprofile",
    "--net=none",
    "--noroot",
    "--caps.drop=all",
    "--seccomp",
    "--private-tmp",
    `--whitelist=${cwd}`,
  ];
  for (const p of allowPaths) {
    if (p) args.push(`--whitelist=${p}`);
  }
  return args;
}
