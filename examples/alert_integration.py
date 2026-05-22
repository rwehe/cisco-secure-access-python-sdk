# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Cisco Secure Access API Client - Class-based implementation with idempotent operations.

This module provides a class-based wrapper around the Cisco Secure Access API,
handling authentication, resource creation with idempotency checks, and proper logging.
"""

import logging
from typing import Any, List, Tuple, Optional

from secure_access import ConditionsAlertRule
from secure_access.models import NotificationInfoAlertRule, NotificationTypeAll, SeverityAlert, StatusAlertRule
from access_token import get_valid_access_token
from secure_access.models.create_alert_rule_request import CreateAlertRuleRequest
from secure_access.api.alert_rules_api import AlertRulesApi

from integrations import CiscoSecureAccessIntegrationClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CiscoSecureAccessAlertIntegrationClient:
    """Client for interacting with Cisco Secure Access APIs with idempotent operations."""

    def __init__(self) -> None:
        """Initialize the client with authentication token."""
        try:
            self.access_token = get_valid_access_token()
            logger.info("Successfully obtained access token")
        except Exception as e:
            logger.error(f"Failed to obtain access token: {e}")
            raise

    def _set_authorization_header(self, api_client: Any) -> None:
        """
        Set the Authorization header for an API client.
        
        Args:
            api_client: The API client instance to configure.
        """
        api_client.api_client.set_default_header(
            "Authorization", f"Bearer {self.access_token}"
        )

    def _build_alert_integration_payload(self, webhook_ids: List[str]) -> CreateAlertRuleRequest:
        """Build the payload for creating a push security events integration."""
        return CreateAlertRuleRequest(
            description="Alert rule created by CiscoSecureAccessAlertIntegrationClient",
            name="Example Alert Rule",
            notification_info=[NotificationInfoAlertRule(
                webhook_ids=webhook_ids,
                type=NotificationTypeAll("webhook"),
            )],
            rule_type_id=10,
            severity=SeverityAlert(1),
            status=StatusAlertRule(1),
            conditions=ConditionsAlertRule(
                match_type="all"
            )
        )
    
    def create_alert_rule(self, webhook_ids: List[str]) -> None:
        """Create a push security events integration with idempotency check."""
        api_client = AlertRulesApi()
        self._set_authorization_header(api_client)

        payload = self._build_alert_integration_payload(webhook_ids)

        try:
            response = api_client.list_alert_rules_without_preload_content()
            if not response.status == 200:
                logger.error(f"Failed to retrieve existing alert rules. Status code: {response.status}")
                return None
            
            existing_alert_rules = response.json()
            logger.info(f"Retrieved existing alert rules: {existing_alert_rules}")
            
            for alert_rule in existing_alert_rules:
                if alert_rule.get("name") == payload.name:
                    logger.info(f"Alert rule '{payload.name}' already exists with ID: {alert_rule.get('id')}")
                    return alert_rule.get("id")

            logger.info(f"Creating new alert rule '{payload.name}'...")
            response = api_client.create_alert_rule_without_preload_content(payload)
            alert_rule = response.json()
            logger.info(f"Successfully created alert rule '{payload.name}': {alert_rule}")
        except Exception as e:
            logger.error(f"Failed to create alert rule '{payload.name}': {e}")
            return None

if __name__ == "__main__":
    client = CiscoSecureAccessAlertIntegrationClient()
    client2 = CiscoSecureAccessIntegrationClient()
    webhook_id = client2.create_webhook_integration()
    client.create_alert_rule([webhook_id])