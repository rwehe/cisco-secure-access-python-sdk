# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from urllib3.util.retry import Retry


class RetryConfig:
    """Retry configuration for API requests using urllib3's Retry."""

    def __init__(self, total=3, backoff_factor=3, status_forcelist=None, allowed_methods=None):
        """Initialize retry configuration.

        Args:
            total: Maximum number of retry attempts.
            backoff_factor: Wait time multiplier between retries:
                {backoff_factor} * (2 ** (retry_number - 1)) seconds.
            status_forcelist: HTTP status codes that trigger a retry.
                Defaults to [429] for rate limiting.
            allowed_methods: HTTP methods that are allowed to be retried.
                Defaults to ["GET", "POST"].
        """
        self.total = total
        self.backoff_factor = backoff_factor
        self.status_forcelist = status_forcelist or [429]
        self.allowed_methods = allowed_methods or ["GET", "POST"]

    def build(self):
        """Build urllib3 Retry object from configuration.

        Returns:
            urllib3.util.retry.Retry: Configured Retry object.
        """
        return Retry(
            total=self.total,
            backoff_factor=self.backoff_factor,
            status_forcelist=self.status_forcelist,
            allowed_methods=self.allowed_methods,
        )


class Config:
    """Centralized configuration for examples.

    Modify the values below to customize behavior across all examples.
    """

    def __init__(self):
        """Initialize configuration with all options disabled."""
        self._retry_config = None

    def enable_retries(
        self, total=3, backoff_factor=3, status_forcelist=None, allowed_methods=None
    ):
        """Enable retry with specified configuration.

        Args:
            total: Maximum number of retry attempts.
            backoff_factor: Wait time multiplier between retries.
            status_forcelist: HTTP status codes that trigger a retry.
            allowed_methods: HTTP methods that are allowed to be retried.

        Returns:
            Config: Self for method chaining.
        """
        self._retry_config = RetryConfig(total, backoff_factor, status_forcelist, allowed_methods)
        return self

    def disable_retries(self):
        """Disable retry.

        Returns:
            Config: Self for method chaining.
        """
        self._retry_config = None
        return self

    def get_retry(self):
        """Get configured urllib3 Retry object.

        Returns:
            urllib3.util.retry.Retry or None: Retry object if enabled, None otherwise.
        """
        return self._retry_config.build() if self._retry_config else None


# DEFAULT CONFIGURATION - Modify these values to change behavior across examples

config = Config()

# Enable retry with defaults (3 retries, 3s backoff, 429 status, GET/POST methods)
config.enable_retries()
# To customize retry settings:
# config.enable_retries(total=5, backoff_factor=2, status_forcelist=[429, 503])

# To disable retry:
# config.disable_retries()
