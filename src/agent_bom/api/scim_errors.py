"""RFC 7644 error bodies shared without loading SCIM authentication or storage."""

from typing import Any

SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def scim_error_body(*, status_code: int, detail: str) -> dict[str, Any]:
    """RFC 7644 Error response body for non-bulk SCIM failures."""
    return {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }
