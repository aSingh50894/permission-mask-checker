# Permission Mask Checker

Checks whether a path's permission bits satisfy a required mask such as "group-writable" or "world-readable". Returns either a boolean or a result object naming the missing bits.

```python
import os
import tempfile
from permission_mask_checker import (
    check_permission_mask,
    requires_permission_mask,
    MASK_GROUP_WRITABLE,
    MASK_OTHER_READABLE,
    MASK_OTHER_WRITABLE,
)

with tempfile.TemporaryDirectory() as d:
    shared = os.path.join(d, "shared.conf")
    with open(shared, "w") as f:
        f.write("key=value\n")
    os.chmod(shared, 0o620)

    # Boolean form
    insecure = requires_permission_mask(shared, MASK_GROUP_WRITABLE)

    # Diagnostic form
    result = check_permission_mask(shared, MASK_OTHER_READABLE)
    if not result.satisfied:
        print(f"missing bits: {oct(result.missing_bits)}")
```

## Why this exists

Auditing code that gates on file permissions tends to reinvent the same five-line `os.stat` snippet, and the snippet is usually wrong in one of two ways: it follows symlinks by default (so a dangling link silently passes), or it compares the whole `st_mode` against an octal literal and trips over the file-type bits. This library does one thing: read the permission bits, mask off the ones you required, and tell you which of those are missing. It does not parse symbolic strings like `g+w`, it does not follow symlinks unless you ask, and it does not treat file-type bits as permissions.

## Exported names

- `check_permission_mask(path, required_mask, *, follow_symlinks=False) -> MaskCheckResult`
- `requires_permission_mask(path, required_mask, *, follow_symlinks=False) -> bool`
- `MaskCheckResult` — frozen dataclass with `satisfied: bool`, `missing_bits: int`, `mode: int`
- `MASK_GROUP_WRITABLE`, `MASK_OTHER_WRITABLE`, `MASK_OTHER_READABLE`, `MASK_SETUID`, `MASK_SETGID` — bit constants, combinable with `|`

## Edge you will hit

By default the checker inspects the link itself, not its target. A symlink carries `0o777` on POSIX, so `requires_permission_mask(link, MASK_OTHER_WRITABLE)` is `True` for a symlink whose target is locked down. If you want to audit the target, pass `follow_symlinks=True` — and note that a dangling symlink then raises `OSError`, which is intentional: a missing target is a caller bug, not a "mask satisfied" result.

Bits outside the low-12 permission set (e.g. `S_IFREG`) passed in `required_mask` are silently stripped before evaluation. A mask of `0o100644` is treated as `0o644`; the file-type bits are not permissions and never count as "missing".

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

