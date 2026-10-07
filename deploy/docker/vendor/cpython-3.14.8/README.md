# CPython tarfile extraction filter repair

The pinned Python 3.14.8 image predates the upstream 3.14 fix for
CVE-2026-87910. During a hardlink fallback, `tarfile` can write an archive member
even when the custom extraction filter returns `None` for that member.

`apply_tarfile_fix.py` applies only the change to `Lib/tarfile.py` from upstream
commit [`a4919937a4e1e69a0d178909c6f20557eca5d1d0`](https://github.com/python/cpython/commit/a4919937a4e1e69a0d178909c6f20557eca5d1d0).
The complete input file must match the Python `v3.14.8` source SHA-256; the
complete output must match that upstream commit's file SHA-256. An unexpected
version or source fails the image build. Applying the same repair twice is safe.

The builder runs a bounded archive regression: a custom filter rejects the
fallback member and the check verifies that no file was written. The runtime
copies the repaired standard library from the identical builder base. Check a
built image with:

```bash
docker run --rm -i --entrypoint python agent-bom:test - --check \
  < deploy/docker/vendor/cpython-3.14.8/apply_tarfile_fix.py
```

The released-image refresh workflow includes this directory in its security
overlay alongside the Dockerfile, so rebuilding an older application tag uses
the same verified runtime repair.

This is an upstream runtime repair, not a vulnerability exception or proof of
application exploitability. It does not change the reported Python version or
remove the scanner's runtime advisory coverage warning. Retire the overlay when
the pinned upstream image includes the fix, after verifying the same regression.

The upstream change is covered by the adjacent Python license.
