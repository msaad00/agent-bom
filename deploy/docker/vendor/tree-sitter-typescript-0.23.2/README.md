# tree-sitter-typescript 0.23.2 build headers

`tree-sitter-typescript==0.23.2` does not publish a musllinux aarch64 wheel.
Its PyPI source distribution also omits `tree_sitter/parser.h` and
`common/scanner.h`, so an Alpine aarch64 source build fails before agent-bom
can be installed.

This directory vendors only the missing headers from the signed upstream
`v0.23.2` tag:

- `typescript/src/tree_sitter/parser.h`
  - source: `https://github.com/tree-sitter/tree-sitter-typescript/blob/v0.23.2/typescript/src/tree_sitter/parser.h`
  - SHA-256: `a1f6ef161fbaf48a0e10fca90ef5290a062462b307b3898aa562993853b9f80a`
- `common/scanner.h`
  - source: `https://github.com/tree-sitter/tree-sitter-typescript/blob/v0.23.2/common/scanner.h`
  - SHA-256: `da66ef2bd14a3f7ea743e25ba068c6c9aae2c3509db200ff80c4a0e6116e564c`
- license: MIT; see `LICENSE`

The root Dockerfile copies the headers into the builder only. The installed
Python package and runtime image contents otherwise remain unchanged.
