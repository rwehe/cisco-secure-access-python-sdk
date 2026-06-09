# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Connectivity smoke tests — verify that local credentials can authenticate
against Cisco Secure Access and that an authenticated read call succeeds.

These tests hit the live API. They are auto-skipped when CLIENT_ID and
CLIENT_SECRET are not set (see tests/conftest.py).

Run only these:
    poetry run pytest -m integration

Skip these (run unit tests only):
    poetry run pytest -m "not integration"
"""

from __future__ import annotations

import base64
import json

import pytest

from secure_access.api.application_lists_api import ApplicationListsApi
from secure_access.api.token_api import TokenApi
from secure_access.api_client import ApiClient
from secure_access.configuration import Configuration
from secure_access.exceptions import ApiException

pytestmark = pytest.mark.integration


def test_token_acquisition(access_token: str) -> None:
    """Credentials should yield a non-empty bearer token."""
    assert isinstance(access_token, str)
    assert access_token, "TokenApi returned an empty access token"
    # OAuth2 bearer tokens are typically substantial; guard against truncation
    # bugs without locking to a specific length.
    assert len(access_token) > 20, "Access token looks suspiciously short"


def test_authenticated_read_call_succeeds(api_client: ApiClient) -> None:
    """A trivial authenticated GET should return a sane payload.

    We use ApplicationListsApi because every tenant has at least the default
    application list, so the response shape is stable across orgs.
    """
    api = ApplicationListsApi(api_client=api_client)
    response = api.get_application_lists_without_preload_content()
    assert response.status == 200, f"Expected 200, got {response.status}"

    payload = json.loads(response.data)
    assert isinstance(payload, dict), f"Expected dict payload, got {type(payload).__name__}"
    assert "results" in payload, f"Response missing 'results' key: {list(payload.keys())[:5]}"
    assert isinstance(payload["results"], list)


def test_invalid_token_is_rejected() -> None:
    """An obviously-bogus token must be rejected — proves auth is enforced.

    Without this, a bug that silently bypasses authentication would still
    pass `test_authenticated_read_call_succeeds`.

    Note: the `_without_preload_content` SDK variant returns the raw HTTP
    response without raising on 4xx, so we assert on `.status` directly.
    """
    config = Configuration(access_token="this-is-not-a-real-token")
    bad_client = ApiClient(configuration=config)
    api = ApplicationListsApi(api_client=bad_client)

    response = api.get_application_lists_without_preload_content()
    assert response.status == 401, (
        f"Expected 401 for invalid token, got {response.status}"
    )


def test_invalid_credentials_rejected_at_token_endpoint() -> None:
    """Bogus client_id/client_secret must fail token acquisition itself."""
    basic = base64.b64encode(b"not-a-real-id:not-a-real-secret").decode()
    with pytest.raises(ApiException) as exc_info:
        TokenApi().create_auth_token(
            grant_type="client_credentials",
            _headers={"Authorization": f"Basic {basic}"},
        )
    # The API should return a 4xx — not 5xx, not silently succeed.
    assert 400 <= exc_info.value.status < 500, (
        f"Expected 4xx for bad credentials, got {exc_info.value.status}"
    )
