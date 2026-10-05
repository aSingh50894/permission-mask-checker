"""Permission Mask Checker.

A tiny, dependency-free library for testing whether a path's permission
bits satisfy a required mask (for example "must not be group-writable").

Only the public functions re-exported here are part of the supported API.
"""

from .core import (
    MASK_GROUP_WRITABLE,
    MASK_OTHER_WRITABLE,
    MASK_OTHER_READABLE,
    MASK_SETUID,
    MASK_SETGID,
    MaskCheckResult,
    check_permission_mask,
    requires_permission_mask,
)

__all__ = [
    "MASK_GROUP_WRITABLE",
    "MASK_OTHER_WRITABLE",
    "MASK_OTHER_READABLE",
    "MASK_SETUID",
    "MASK_SETGID",
    "MaskCheckResult",
    "check_permission_mask",
    "requires_permission_mask",
]
