# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Shared pytest configuration and fixtures.

- Loads CLIENT_ID / CLIENT_SECRET from a project-root `.env` so tests behave
  the same way the example scripts do.
- Provides a session-scoped `access_token` fixture that acquires one token
  via TokenApi and reuses it for every integration test in a run.
- Provides a configured `api_client` fixture for the SDK.
- Tests marked `@pytest.mark.integration` are auto-skipped when credentials
  are not available, so unit-only runs stay green offline / in CI.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional

import pytest
from dotenv import load_dotenv

from secure_access.api.token_api import TokenApi
from secure_access.api_client import ApiClient
from secure_access.configuration import Configuration

# Load .env from the repo root once at import time.
_REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_REPO_ROOT / ".env")


def _have_credentials() -> bool:
    return bool(os.getenv("CLIENT_ID")) and bool(os.getenv("CLIENT_SECRET"))


def pytest_collection_modifyitems(config, items):
    """Auto-skip integration tests when no credentials are configured."""
    if _have_credentials():
        return
    skip_marker = pytest.mark.skip(
        reason="CLIENT_ID / CLIENT_SECRET not set; skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def credentials() -> tuple[str, str]:
    """Return (client_id, client_secret) or skip if either is missing."""
    cid = os.getenv("CLIENT_ID")
    csecret = os.getenv("CLIENT_SECRET")
    if not cid or not csecret:
        pytest.skip("CLIENT_ID / CLIENT_SECRET not set in environment or .env")
    return cid, csecret


def _acquire_token(client_id: str, client_secret: str) -> str:
    """Acquire an OAuth2 access token via the SDK's TokenApi."""
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    response = TokenApi().create_auth_token(
        grant_type="client_credentials",
        _headers={"Authorization": f"Basic {basic}"},
    )
    return response.access_token


@pytest.fixture(scope="session")
def access_token(credentials: tuple[str, str]) -> str:
    """One token per test session — avoids hammering /auth/v2/token."""
    cid, csecret = credentials
    return _acquire_token(cid, csecret)


@pytest.fixture(scope="session")
def api_client(access_token: str) -> ApiClient:
    """Configured ApiClient ready for any *Api(api_client=...) consumer."""
    configuration = Configuration(access_token=access_token)
    return ApiClient(configuration=configuration)
