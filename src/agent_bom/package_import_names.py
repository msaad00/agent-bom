"""PyPI distribution name ↔ import name aliases.

A Python distribution and the module you import from it are frequently not the
same string: you install ``PyYAML`` and write ``import yaml``. Static analysis
sees the import name, while an SCA finding and its OSV advisory carry the
distribution name, so any code that compares the two directly will miss real
matches.

Only genuine, well-known divergences belong here. Where a distribution's import
name is just its own name with separators normalized (``python-json-logger`` →
``python_json_logger``), :func:`import_names_for_distribution` derives it and no
table entry is needed.
"""

from __future__ import annotations

# distribution (normalized: lowercase, dashes) → import names it provides.
_DISTRIBUTION_TO_IMPORTS: dict[str, tuple[str, ...]] = {
    "attrs": ("attr", "attrs"),
    "beautifulsoup4": ("bs4",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "pillow": ("pil",),
    "protobuf": ("google",),
    "pycryptodome": ("crypto",),
    "pycryptodomex": ("cryptodome",),
    "pyjwt": ("jwt",),
    "pymysql": ("pymysql",),
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "python-docx": ("docx",),
    "python-magic": ("magic",),
    "python-multipart": ("multipart",),
    "python-pptx": ("pptx",),
    "scikit-image": ("skimage",),
    "scikit-learn": ("sklearn",),
    "msgpack-python": ("msgpack",),
    "typing-extensions": ("typing_extensions",),
    "memcached": ("memcache",),
    "faiss-cpu": ("faiss",),
    "faiss-gpu": ("faiss",),
    "google-auth": ("google",),
    "google-api-python-client": ("googleapiclient",),
    "azure-identity": ("azure",),
    "grpcio": ("grpc",),
    "setuptools": ("setuptools", "pkg_resources"),
}


def _normalize_distribution(name: str) -> str:
    """Normalize a distribution name to its PEP 503 comparison form."""
    return name.strip().lower().replace("_", "-")


def import_names_for_distribution(distribution: str) -> tuple[str, ...]:
    """Return the lowercase import names a PyPI *distribution* may provide.

    Always includes the distribution's own normalized forms, so callers can use
    the result as the complete candidate set for a lookup.
    """
    normalized = _normalize_distribution(distribution)
    if not normalized:
        return ()

    candidates: list[str] = [normalized, normalized.replace("-", "_")]
    candidates.extend(_DISTRIBUTION_TO_IMPORTS.get(normalized, ()))

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return tuple(ordered)
