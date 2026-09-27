"""Canonical distro rules for ecosystem version comparison."""

from __future__ import annotations

import re


def _debian_order_char(ch: str | None) -> int:
    if ch is None:
        return 0
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_debian_part(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            lc = left[i] if i < len(left) and not left[i].isdigit() else None
            rc = right[j] if j < len(right) and not right[j].isdigit() else None
            if lc == rc:
                if lc is not None:
                    i += 1
                if rc is not None:
                    j += 1
                continue
            lo = _debian_order_char(lc)
            ro = _debian_order_char(rc)
            if lo != ro:
                return (lo > ro) - (lo < ro)
            if lc is not None:
                i += 1
            if rc is not None:
                j += 1

        left_digits = ""
        while i < len(left) and left[i].isdigit():
            left_digits += left[i]
            i += 1
        right_digits = ""
        while j < len(right) and right[j].isdigit():
            right_digits += right[j]
            j += 1

        left_digits = left_digits.lstrip("0") or "0"
        right_digits = right_digits.lstrip("0") or "0"
        if len(left_digits) != len(right_digits):
            return (len(left_digits) > len(right_digits)) - (len(left_digits) < len(right_digits))
        if left_digits != right_digits:
            return (left_digits > right_digits) - (left_digits < right_digits)
    return 0


def _split_debian_version(version: str) -> tuple[int, str, str]:
    epoch_str, _, remainder = version.partition(":")
    if remainder:
        try:
            epoch = int(epoch_str)
        except ValueError:
            epoch = 0
    else:
        epoch = 0
        remainder = version
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    return epoch, upstream, revision


def _compare_debian_versions(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _split_debian_version(left)
    right_epoch, right_upstream, right_revision = _split_debian_version(right)
    if left_epoch != right_epoch:
        return (left_epoch > right_epoch) - (left_epoch < right_epoch)
    upstream_cmp = _compare_debian_part(left_upstream, right_upstream)
    if upstream_cmp:
        return upstream_cmp
    return _compare_debian_part(left_revision, right_revision)


def _consume_rpm_segment(value: str, start: int) -> tuple[str, int]:
    end = start
    kind = value[start].isdigit()
    while end < len(value) and value[end].isdigit() == kind and value[end].isalnum():
        end += 1
    return value[start:end], end


def _compare_rpm_segments(left_seg: str, right_seg: str) -> int:
    """Compare numeric or alphabetic RPM segments after separator handling."""
    left_is_num = left_seg[0].isdigit()
    right_is_num = right_seg[0].isdigit()

    if left_is_num != right_is_num:
        return 1 if left_is_num else -1

    if left_is_num:
        left_norm = left_seg.lstrip("0") or "0"
        right_norm = right_seg.lstrip("0") or "0"
        if len(left_norm) != len(right_norm):
            return (len(left_norm) > len(right_norm)) - (len(left_norm) < len(right_norm))
        if left_norm != right_norm:
            return (left_norm > right_norm) - (left_norm < right_norm)
    else:
        if left_seg != right_seg:
            return (left_seg > right_seg) - (left_seg < right_seg)

    return 0


def _compare_rpm_like(left: str, right: str) -> int:
    i = j = 0
    while True:
        while i < len(left) and not left[i].isalnum() and left[i] not in "~^":
            i += 1
        while j < len(right) and not right[j].isalnum() and right[j] not in "~^":
            j += 1

        if i < len(left) and left[i] == "~" or j < len(right) and right[j] == "~":
            if not (i < len(left) and left[i] == "~"):
                return 1
            if not (j < len(right) and right[j] == "~"):
                return -1
            i += 1
            j += 1
            continue

        if i < len(left) and left[i] == "^" or j < len(right) and right[j] == "^":
            if i >= len(left):
                return -1
            if j >= len(right):
                return 1
            if left[i] != "^":
                return 1
            if right[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= len(left) or j >= len(right):
            break

        left_seg, i = _consume_rpm_segment(left, i)
        right_seg, j = _consume_rpm_segment(right, j)
        segment_order = _compare_rpm_segments(left_seg, right_seg)
        if segment_order:
            return segment_order

    if i >= len(left) and j >= len(right):
        return 0
    return -1 if i >= len(left) else 1


def _split_epoch(version: str) -> tuple[int, str]:
    epoch_str, sep, rest = version.partition(":")
    if not sep:
        return 0, version
    try:
        return int(epoch_str), rest
    except ValueError:
        return 0, version


def _compare_rpm_versions(left: str, right: str) -> int:
    left_epoch, left_rest = _split_epoch(left)
    right_epoch, right_rest = _split_epoch(right)
    if left_epoch != right_epoch:
        return (left_epoch > right_epoch) - (left_epoch < right_epoch)
    return _compare_rpm_like(left_rest, right_rest)


_APK_PRE_SUFFIXES = ("alpha", "beta", "pre", "rc")


_APK_POST_SUFFIXES = ("cvs", "svn", "git", "hg", "p")


_APK_SUFFIX_RE = re.compile(r"_([a-z]+)(\d*)")


def _apk_suffix_rank(name: str) -> int:
    """Rank an apk suffix name relative to the release (0).

    Pre-release suffixes rank negative (below the release), post-release
    suffixes rank positive (above), ordered within each class. An unrecognised
    suffix ranks as release-level so it never silently outranks a real fix.
    """
    if name in _APK_PRE_SUFFIXES:
        return _APK_PRE_SUFFIXES.index(name) - len(_APK_PRE_SUFFIXES)
    if name in _APK_POST_SUFFIXES:
        return _APK_POST_SUFFIXES.index(name) + 1
    return 0


def _apk_split_suffix(base: str) -> tuple[str, str]:
    """Split the numeric/letter core from the ``_suffix`` tail of an apk base."""
    idx = base.find("_")
    if idx == -1:
        return base, ""
    return base[:idx], base[idx:]


def _apk_suffix_key(suffix: str) -> list[tuple[int, int]]:
    return [(_apk_suffix_rank(name), int(num) if num else 0) for name, num in _APK_SUFFIX_RE.findall(suffix)]


def _compare_apk_suffix_keys(left: list[tuple[int, int]], right: list[tuple[int, int]]) -> int:
    """Compare two apk suffix keys, treating an exhausted side as the release.

    A missing suffix is the release: it outranks any pre-release suffix and is
    outranked by any post-release suffix on the other side.
    """
    for i in range(max(len(left), len(right))):
        if i >= len(left):
            rank = right[i][0]
            return 1 if rank < 0 else -1 if rank > 0 else 0
        if i >= len(right):
            rank = left[i][0]
            return -1 if rank < 0 else 1 if rank > 0 else 0
        if left[i] != right[i]:
            return (left[i] > right[i]) - (left[i] < right[i])
    return 0


def _compare_apk_versions(left: str, right: str) -> int:
    def _split_revision(value: str) -> tuple[str, int]:
        if "-r" in value:
            base, revision = value.rsplit("-r", 1)
            try:
                return base, int(revision)
            except ValueError:
                return base, 0
        return value, 0

    left_base, left_rev = _split_revision(left)
    right_base, right_rev = _split_revision(right)

    # A ``~<commit>`` fuzzy/commit suffix is compared last, as low-priority
    # metadata; core + apk suffix ordering decide first.
    left_core, _, left_hash = left_base.partition("~")
    right_core, _, right_hash = right_base.partition("~")

    left_main, left_suffix = _apk_split_suffix(left_core)
    right_main, right_suffix = _apk_split_suffix(right_core)

    base_cmp = _compare_rpm_like(left_main, right_main)
    if base_cmp:
        return base_cmp
    suffix_cmp = _compare_apk_suffix_keys(_apk_suffix_key(left_suffix), _apk_suffix_key(right_suffix))
    if suffix_cmp:
        return suffix_cmp
    if left_hash != right_hash:
        return (left_hash > right_hash) - (left_hash < right_hash)
    return (left_rev > right_rev) - (left_rev < right_rev)
