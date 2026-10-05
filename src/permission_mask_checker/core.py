"""Core permission-mask checking logic.

The module is deliberately small. ``check_permission_mask`` reads the
filesystem entry's ``st_mode`` once, masks off the permission bits we care
about, and reports which required bits are missing. ``requires_permission_mask``
is a thin boolean wrapper for callers that only want a yes/no answer.

Design decisions that are not obvious from the code:

* We work on the low 12 bits of ``st_mode`` (the setuid/setgid/sticky bits and
  the nine ``rwx`` permission bits). Callers pass symbolic constants such as
  ``MASK_GROUP_WRITABLE``; the checker never parses strings like ``g+w``. Two
  earlier drafts tried to accept octal strings and symbolic strings and the
  combinatorial ambiguity made the test suite contradictory, so we dropped
  both. A constant is unambiguous and trivially composable with ``|``.

* A mask bit that is *required* but *absent* is reported as missing. A mask
  bit that is *required* and *present* is satisfied. We never complain about
  permission bits the path has but the mask does not require; this library is
  a "does it meet the bar" checker, not a "are the bits exactly equal"
  checker. Callers wanting exact equality can compare ``st_mode & 0o7777``
  themselves.

* We do not follow symlinks by default. Permission checks on the link target
  silently succeed when the target does not exist, which is exactly the kind
  of surprise that lets an insecure file slip through an audit. The default is
  ``follow_symlinks=False``; callers that genuinely want to audit the target
  pass ``follow_symlinks=True`` and accept responsibility for the dangling-link
  case (which raises ``OSError`` from ``os.lstat``).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Union

# Symbolic masks for the most common audit questions. Callers can combine
# these with bitwise-OR to build a richer required-mask.
MASK_GROUP_WRITABLE: int = stat.S_IWGRP
MASK_OTHER_WRITABLE: int = stat.S_IWOTH
MASK_OTHER_READABLE: int = stat.S_IROTH
MASK_SETUID: int = stat.S_ISUID
MASK_SETGID: int = stat.S_ISGID

# The bits ``st_mode`` can carry that we consider meaningful for this check.
# This is the setuid/setgid/sticky triplet plus the nine rwx bits.
_RELEVANT_BITS: int = (
    stat.S_ISUID
    | stat.S_ISGID
    | stat.S_ISVTX
    | stat.S_IRWXU
    | stat.S_IRWXG
    | stat.S_IRWXO
)

PathLike = Union[str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"]


@dataclass(frozen=True)
class MaskCheckResult:
    """Outcome of a permission-mask check.

    ``satisfied`` is ``True`` when every bit in the required mask is present
    on the path. ``missing_bits`` is the subset of required bits that are not
    set, expressed in raw integer form so callers can format it however they
    like (octal, symbolic, named). ``mode`` is the ``st_mode`` value we
    inspected, included so callers can build richer diagnostics without a
    second ``stat`` call.
    """

    satisfied: bool
    missing_bits: int
    mode: int


def check_permission_mask(
    path: PathLike,
    required_mask: int,
    *,
    follow_symlinks: bool = False,
) -> MaskCheckResult:
    """Check that ``path`` carries every bit in ``required_mask``.

    Parameters
    ----------
    path:
        Filesystem path to inspect. ``str``, ``bytes``, and any
        ``os.PathLike`` are accepted and forwarded to ``os.lstat``/
        ``os.stat`` unchanged.
    required_mask:
        Bitwise-OR of permission bits (e.g. ``MASK_GROUP_WRITABLE``) that
        must all be present. Bits outside the low-12 permission set are
        ignored, so passing ``0o7777`` is equivalent to passing ``0o7777 &
        0o7777`` and never carries file-type bits by accident.
    follow_symlinks:
        If ``False`` (the default) the link itself is inspected via
        ``os.lstat``. If ``True`` the target is inspected via ``os.stat``;
        a dangling symlink then surfaces as the ``OSError`` from ``stat``.

    Returns
    -------
    MaskCheckResult
        ``satisfied`` is ``True`` iff every required bit is present.
        ``missing_bits`` is ``required_mask & ~mode`` restricted to the
        relevant permission bits. ``mode`` is the raw ``st_mode``.

    Raises
    ------
    OSError
        Propagated from ``os.lstat``/``os.stat`` if the path does not exist
        or is inaccessible. We deliberately do not catch this: a missing
        path is a caller bug, not a "mask not satisfied" result.
    """
    stat_fn = os.stat if follow_symlinks else os.lstat
    st = stat_fn(path)
    mode = st.st_mode

    # Restrict the required mask to bits that actually live in the permission
    # portion of st_mode. A caller passing 0o100777 (regular file + rwxrwxrwx)
    # would otherwise be asking for the S_IFREG bit, which is not a permission
    # and would always be "missing" on a directory. Masking keeps the contract
    # honest: only permission-relevant bits are evaluated.
    effective_required = required_mask & _RELEVANT_BITS

    present_bits = mode & effective_required
    missing_bits = effective_required & ~present_bits

    return MaskCheckResult(
        satisfied=missing_bits == 0,
        missing_bits=missing_bits,
        mode=mode,
    )


def requires_permission_mask(
    path: PathLike,
    required_mask: int,
    *,
    follow_symlinks: bool = False,
) -> bool:
    """Return ``True`` iff every bit in ``required_mask`` is set on ``path``.

    Thin convenience wrapper around :func:`check_permission_mask` for callers
    that only need a boolean and do not care which bits were missing.
    """
    return check_permission_mask(
        path, required_mask, follow_symlinks=follow_symlinks
    ).satisfied
