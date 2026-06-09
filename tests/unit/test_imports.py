# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests — no network, no credentials.

These exist mainly to catch obvious breakage early: the SDK package doesn't
import cleanly, an *Api class disappears, etc. They are deliberately tiny.
"""

from __future__ import annotations

import importlib
import pkgutil


def test_top_level_package_imports() -> None:
    """The `secure_access` package must import cleanly."""
    import secure_access  # noqa: F401


def test_core_modules_import() -> None:
    """The handful of modules every example touches must be importable."""
    from secure_access.api_client import ApiClient  # noqa: F401
    from secure_access.configuration import Configuration  # noqa: F401
    from secure_access.exceptions import ApiException  # noqa: F401
    from secure_access.api.token_api import TokenApi  # noqa: F401


def test_every_api_module_imports() -> None:
    """Walk `secure_access.api` and import every submodule.

    Catches cases where a generated module has a syntax error or references
    a model that was removed, without us having to maintain a hand-written
    list of API names.
    """
    import secure_access.api as api_pkg

    failures: list[tuple[str, str]] = []
    for mod_info in pkgutil.iter_modules(api_pkg.__path__):
        full_name = f"{api_pkg.__name__}.{mod_info.name}"
        try:
            importlib.import_module(full_name)
        except Exception as e:  # noqa: BLE001 — we want to report all failures
            failures.append((full_name, f"{type(e).__name__}: {e}"))

    assert not failures, "API modules failed to import:\n" + "\n".join(
        f"  - {name}: {err}" for name, err in failures
    )
