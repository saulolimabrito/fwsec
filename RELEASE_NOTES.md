# fwsec 1.5.1

## Legacy nftables hotfix

- nftables 1.0.2/1.0.4 omit chain comments from JSON, and some old kernels
  discard chain comments altogether. Add a portable, inert first-rule sentinel
  (anonymous counter plus exact comment, no verdict). Validate its exact shape
  and position; arbitrary rule comments never authorize ownership. Retain a
  strict scoped text fallback for existing chain declarations.
- Report already-completed rollback accurately instead of claiming a worker
  remains armed. Do not retry 1.5.0; upgrade to 1.5.1 instead.

## Included from 1.5.0

- Checked atomic nftables application, detached rollback and serialized CLI writers.
- Confirmation defers persistence; rollback retains remaining temporary-ban life.
- Scoped changes preserve unrelated tables/chains and CrowdSec sets.
- Reviewed CSF/UFW xtables migration preserves ordered IPv4/IPv6 rules,
  endpoint/interface constraints and directional defaults. Unsupported NAT,
  ipsets, extensions and native firewalld policies block migration, never vanish.
- Optional `OUTPUT_POLICY=drop`; existing configurations keep their defaults.

## Upgrade transition

Run `fwsec --upgrade` after this release is published. The installer stages a
separate versioned environment, validates the candidate, applies a provisional
transaction, atomically switches the executable wrapper and confirms persistence.
Old environments are retained. Failed activation or confirmation restores the
previous wrapper, rules and persistence; an independent watchdog stays armed
until confirmation succeeds.

Unmarked legacy installations are adopted automatically only after comparing
the live kernel policy with the configured candidate using unhooked scratch
tables. Rule order, actions, defaults, sets and remaining ban lifetimes must
match. Anonymous counters and fwsec ownership comments do not change policy.
Scratch tables never filter traffic and are cleaned up.

**Custom/divergent legacy rules refuse the upgrade before activation.** Review
the configuration and custom policy; do not blindly force `--adopt-legacy`.
Disabled/inactive installations, symlinked executables or administrator-owned
loaders with a global flush require manual review. Preserving access takes
priority over completing an unattended upgrade.

This release does not deploy itself to servers. Migration still requires a new
SSH session to confirm and a separate `--migration-finalize` operation.
