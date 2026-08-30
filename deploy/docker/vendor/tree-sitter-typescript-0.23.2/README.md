# tree-sitter-typescript 0.23.2 build header

`tree-sitter-typescript==0.23.2` does not publish a musllinux aarch64 wheel.
Its PyPI source distribution also omits `tree_sitter/parser.h`, so an Alpine
aarch64 source build fails before agent-bom can be installed.

This directory vendors only the missing header from the signed upstream
`v0.23.2` tag:

- source: `https://github.com/tree-sitter/tree-sitter-typescript/blob/v0.23.2/typescript/src/tree_sitter/parser.h`
- SHA-256: `a1f6ef161fbaf48a0e10fca90ef5290a062462b307b3898aa562993853b9f80a`
- license: MIT; see `LICENSE`

The root Dockerfile copies the header into the builder only. The installed
Python package and runtime image contents otherwise remain unchanged.
