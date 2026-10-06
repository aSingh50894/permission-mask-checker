"""Tests for permission_mask_checker.core.

Every test creates real files in a ``tempfile.TemporaryDirectory`` and sets
explicit permission bits with ``os.chmod``, so results depend only on the bits
we wrote, never on the umask the test runner happens to carry.

We never assert on wall-clock time and never rely on the current user being
able to create setuid files (many CI containers forbid it). Where a bit cannot
be set we skip with ``skipTest`` rather than assert a behaviour we cannot
reproduce deterministically.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest

from permission_mask_checker.core import (
    MASK_GROUP_WRITABLE,
    MASK_OTHER_READABLE,
    MASK_OTHER_WRITABLE,
    MASK_SETGID,
    MASK_SETUID,
    MaskCheckResult,
    check_permission_mask,
    requires_permission_mask,
)


def _can_set_mode(path: str, mode: int) -> bool:
    """Return True if we can actually set ``mode`` on ``path``.

    Some containers run as root-with-locked-capabilities or as a non-root
    user who cannot grant setuid/setgid. Rather than assert behaviour we
    cannot reproduce, the caller skips when this returns False.
    """
    try:
        os.chmod(path, mode)
        return (os.lstat(path).st_mode & mode) == mode
    except OSError:
        return False


class CheckPermissionMaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "target")
        with open(self.path, "wb"):
            pass

    def _set_mode(self, mode: int) -> None:
        os.chmod(self.path, mode)

    def test_all_required_bits_present(self) -> None:
        self._set_mode(0o644)
        result = check_permission_mask(self.path, MASK_OTHER_READABLE)
        self.assertTrue(result.satisfied)
        self.assertEqual(result.missing_bits, 0)
        self.assertEqual(result.mode & 0o7777, 0o644)

    def test_missing_required_bit_reported(self) -> None:
        # 0o600 has no world-readable bit.
        self._set_mode(0o600)
        result = check_permission_mask(self.path, MASK_OTHER_READABLE)
        self.assertFalse(result.satisfied)
        self.assertEqual(result.missing_bits, MASK_OTHER_READABLE)

    def test_mask_combination_satisfied(self) -> None:
        self._set_mode(0o666)
        combined = MASK_GROUP_WRITABLE | MASK_OTHER_WRITABLE
        result = check_permission_mask(self.path, combined)
        self.assertTrue(result.satisfied)
        self.assertEqual(result.missing_bits, 0)

    def test_mask_combination_partially_satisfied(self) -> None:
        # 0o620: group has rwx, world has nothing.
        self._set_mode(0o620)
        combined = MASK_GROUP_WRITABLE | MASK_OTHER_WRITABLE
        result = check_permission_mask(self.path, combined)
        self.assertFalse(result.satisfied)
        self.assertEqual(result.missing_bits, MASK_OTHER_WRITABLE)

    def test_file_type_bits_in_mask_are_ignored(self) -> None:
        # 0o100644 is "regular file + rw-r--r--". Including S_IFREG in the
        # required mask must NOT make the check fail; file-type bits are not
        # permissions and are stripped before evaluation.
        self._set_mode(0o644)
        required = MASK_OTHER_READABLE | stat.S_IFREG
        result = check_permission_mask(self.path, required)
        self.assertTrue(result.satisfied)

    def test_nonexistent_path_raises_oserror(self) -> None:
        missing = os.path.join(self._tmp.name, "does-not-exist")
        with self.assertRaises(OSError):
            check_permission_mask(missing, MASK_OTHER_READABLE)

    def test_result_is_maskcheckresult_instance(self) -> None:
        self._set_mode(0o644)
        result = check_permission_mask(self.path, MASK_OTHER_READABLE)
        self.assertIsInstance(result, MaskCheckResult)

    def test_follow_symlinks_true_inspects_target(self) -> None:
        target = os.path.join(self._tmp.name, "target_file")
        link = os.path.join(self._tmp.name, "link")
        with open(target, "wb"):
            pass
        os.chmod(target, 0o644)
        os.symlink(target, link)
        # The link itself has 0o777 perms (typical for symlinks); the target
        # has 0o644. Following must read the target's bits.
        result = check_permission_mask(link, MASK_OTHER_READABLE, follow_symlinks=True)
        self.assertTrue(result.satisfied)

    def test_follow_symlinks_false_inspects_link_not_target(self) -> None:
        target = os.path.join(self._tmp.name, "target_file")
        link = os.path.join(self._tmp.name, "link")
        with open(target, "wb"):
            pass
        os.chmod(target, 0o600)  # target not world-readable
        os.symlink(target, link)
        # Default (follow_symlinks=False) inspects the link. Symlink bits are
        # conventionally 0o777 on POSIX, so the world-readable bit is present
        # on the link even though it is absent on the target.
        result = check_permission_mask(link, MASK_OTHER_READABLE)
        self.assertTrue(result.satisfied)

    def test_dangling_symlink_with_follow_raises_oserror(self) -> None:
        link = os.path.join(self._tmp.name, "dangling")
        os.symlink(os.path.join(self._tmp.name, "nope"), link)
        with self.assertRaises(OSError):
            check_permission_mask(link, MASK_OTHER_READABLE, follow_symlinks=True)

    def test_dangling_symlink_without_follow_does_not_raise(self) -> None:
        # The link inode exists even if its target does not, so the default
        # non-following path must succeed and report the link's own bits.
        link = os.path.join(self._tmp.name, "dangling")
        os.symlink(os.path.join(self._tmp.name, "nope"), link)
        result = check_permission_mask(link, MASK_OTHER_READABLE)
        self.assertTrue(result.satisfied)

    def test_setuid_bit_when_settable(self) -> None:
        self._set_mode(0o4755)
        if not _can_set_mode(self.path, 0o4755):
            self.skipTest("cannot set setuid bit in this environment")
        result = check_permission_mask(self.path, MASK_SETUID)
        self.assertTrue(result.satisfied)

    def test_setuid_bit_missing(self) -> None:
        self._set_mode(0o755)
        result = check_permission_mask(self.path, MASK_SETUID)
        self.assertFalse(result.satisfied)
        self.assertEqual(result.missing_bits, MASK_SETUID)


class RequiresPermissionMaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "target")
        with open(self.path, "wb"):
            pass

    def test_returns_bool_true(self) -> None:
        os.chmod(self.path, 0o644)
        self.assertIs(
            requires_permission_mask(self.path, MASK_OTHER_READABLE), True
        )

    def test_returns_bool_false(self) -> None:
        os.chmod(self.path, 0o600)
        self.assertIs(
            requires_permission_mask(self.path, MASK_OTHER_READABLE), False
        )

    def test_combined_mask(self) -> None:
        os.chmod(self.path, 0o660)
        combined = MASK_GROUP_WRITABLE | MASK_OTHER_WRITABLE
        # group-writable yes, world-writable no
        self.assertIs(requires_permission_mask(self.path, combined), False)
        os.chmod(self.path, 0o666)
        self.assertIs(requires_permission_mask(self.path, combined), True)


class DirectoryTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "subdir")
        os.mkdir(self.path)

    def test_directory_group_writable(self) -> None:
        os.chmod(self.path, 0o770)
        result = check_permission_mask(self.path, MASK_GROUP_WRITABLE)
        self.assertTrue(result.satisfied)
        self.assertEqual(result.missing_bits, 0)

    def test_directory_setgid_when_settable(self) -> None:
        os.chmod(self.path, 0o2770)
        if not _can_set_mode(self.path, 0o2770):
            self.skipTest("cannot set setgid bit in this environment")
        result = check_permission_mask(self.path, MASK_SETGID)
        self.assertTrue(result.satisfied)


if __name__ == "__main__":
    unittest.main()
