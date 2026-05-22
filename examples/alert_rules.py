# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Alert Rules Management Example for Cisco Secure Access API.

This module provides a comprehensive example of managing alert rules using
the Cisco Secure Access Python SDK. It demonstrates CRUD operations:
- List all alert rules
- Get a specific alert rule by ID
- Create a new alert rule
- Update an existing alert rule
- Delete alert rules
- Update the status of alert rules

Usage:
    python alert_rules.py list
    python alert_rules.py get --id <rule_id>
    python alert_rules.py create --name "My Alert" --rule-type-id 10 --severity 1
    python alert_rules.py create --name "My Alert" --rule-type-id 10 --severity 1 \\
        --conditions allAccessRules= --email admin@example.com
    python alert_rules.py update --id <rule_id> --name "Updated Alert" --rule-type-id 10 --severity 2
    python alert_rules.py delete --ids <rule_id1> <rule_id2>
    python alert_rules.py update-status --ids <rule_id1> --status 1

Requirements:
    - Set CLIENT_ID and CLIENT_SECRET environment variables
    - Ensure all dependencies in requirements.txt are installed

API Documentation:
    - https://developer.cisco.com/docs/cloud-security/list-alert-rules/
    - https://developer.cisco.com/docs/cloud-security/get-alert-rule/
    - https://developer.cisco.com/docs/cloud-security/create-alert-rule/
    - https://developer.cisco.com/docs/cloud-security/update-alert-rule/
    - https://developer.cisco.com/docs/cloud-security/delete-alert-rules/
    - https://developer.cisco.com/docs/cloud-security/update-status-of-alert-rules/
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from access_token import get_valid_access_token
from secure_access.api.alert_rules_api import AlertRulesApi
from secure_access.models import (
    AlertRule,
    ConditionsAlertRule,
    ConditionsAlertRuleRowsInner,
    CreateAlertRule201Response,
    CreateAlertRuleRequest,
    DeleteAlertRules200Response,
    DeleteAlertRulesRequest,
    NotificationInfoAlertRule,
    NotificationTypeAll,
    SeverityAlert,
    StatusAlertRule,
    UpdateAlertRule200Response,
    UpdateAlertRuleRequest,
    UpdateAlertRulesStatusRequest,
    UpdateAlertRulesStatus200Response,
)
from secure_access.exceptions import ApiException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertRulesClient:
    """
    Client for managing Cisco Secure Access Alert Rules.
    
    Provides methods for CRUD operations on alert rules including:
    - Listing all alert rules
    - Getting a specific alert rule
    - Creating new alert rules
    - Updating existing alert rules
    - Deleting alert rules
    - Updating alert rule status
    """

    def __init__(self) -> None:
        """
        Initialize the AlertRulesClient with authentication.
        
        Raises:
            ValueError: If required environment variables are not set.
            Exception: If access token generation fails.
        """
        try:
            self.access_token = get_valid_access_token()
            logger.info("Successfully obtained access token")
        except Exception as e:
            logger.error(f"Failed to obtain access token: {e}")
            raise

    def _get_api_client(self) -> AlertRulesApi:
        """
        Create and configure an AlertRulesApi client with authorization header.
        
        Returns:
            AlertRulesApi: Configured API client instance.
        """
        api_client = AlertRulesApi()
        api_client.api_client.set_default_header(
            "Authorization", f"Bearer {self.access_token}"
        )
        return api_client

    def _build_condition_rows(
        self,
        conditions_rows: Optional[List[Dict[str, str]]],
        rule_type_id: int,
    ) -> List[ConditionsAlertRuleRowsInner]:
        """
        Build condition rows for an alert rule.
        
        If conditions_rows is provided, uses those. Otherwise, applies a sensible
        default based on the rule_type_id.
        
        Default condition rows by rule_type_id:
            - 10 (Access Rule Changes): allAccessRules
            - 1, 2 (Connectivity): allTunnelGroups
            - 3-8 (API Anomalies): allApiKeys
            - 9 (Data Usage): allDataUsage
            - 11-17 (Behavior Analytics): allIdentities
        """
        if conditions_rows:
            return [
                ConditionsAlertRuleRowsInner(var_field=row["field"], value=row.get("value", ""))
                for row in conditions_rows
            ]

        # Default condition rows based on rule type
        default_fields = {
            10: "allAccessRules",
        }
        field = default_fields.get(rule_type_id, "allAccessRules")
        return [ConditionsAlertRuleRowsInner(var_field=field, value="")]

    # =========================================================================
    # LIST ALERT RULES
    # =========================================================================
    def list_alert_rules(self) -> List[AlertRule]:
        """
        List all alert rules for the organization.
        
        Returns:
            List[AlertRule]: List of AlertRule model objects.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = AlertRulesClient()
            >>> rules = client.list_alert_rules()
            >>> for rule in rules:
            ...     print(f"Rule: {rule.name} (ID: {rule.id})")
        """
        api_client = self._get_api_client()
        logger.info("Retrieving all alert rules...")

        try:
            alert_rules = api_client.list_alert_rules()
            logger.info(f"Successfully retrieved {len(alert_rules)} alert rules")
            
            for rule in alert_rules:
                logger.debug(
                    f"Rule ID: {rule.id}, "
                    f"Name: {rule.name}, "
                    f"Status: {rule.status}, "
                    f"Severity: {rule.severity}"
                )
            
            return alert_rules

        except ApiException as e:
            logger.error(f"API error listing alert rules: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing alert rules: {e}")
            raise

    # =========================================================================
    # GET ALERT RULE BY ID
    # =========================================================================
    def get_alert_rule_by_id(self, rule_id: int) -> Optional[AlertRule]:
        """
        Get a specific alert rule by its ID.
        
        Args:
            rule_id (int): The unique identifier of the alert rule.
            
        Returns:
            Optional[AlertRule]: The AlertRule model object, or None if not found.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = AlertRulesClient()
            >>> rule = client.get_alert_rule_by_id(12345)
            >>> if rule:
            ...     print(f"Found rule: {rule.name}")
        """
        api_client = self._get_api_client()
        logger.info(f"Retrieving alert rule with ID: {rule_id}")

        try:
            alert_rule = api_client.get_alert_rule_by_id(rule_id=rule_id)
            logger.info(f"Successfully retrieved alert rule: {alert_rule.name}")
            return alert_rule

        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Alert rule {rule_id} not found")
                return None
            logger.error(f"API error getting alert rule {rule_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting alert rule {rule_id}: {e}")
            raise

    # =========================================================================
    # CREATE ALERT RULE
    # =========================================================================
    def create_alert_rule(
        self,
        name: str,
        rule_type_id: int,
        severity: int,
        status: int = 1,
        description: Optional[str] = None,
        conditions_match_type: str = "all",
        conditions_rows: Optional[List[Dict[str, str]]] = None,
        webhook_ids: Optional[List[str]] = None,
        email_recipients: Optional[List[str]] = None,
    ) -> Optional[AlertRule]:
        """
        Create a new alert rule (idempotent).
        
        If an alert rule with the same name already exists, returns the existing
        rule instead of failing. This makes the operation safe to retry.
        
        Args:
            name (str): The name of the alert rule (max 255 characters).
            rule_type_id (int): The identifier of the rule type.
            severity (int): The severity level (1=High, 2=Medium, 3=Low).
            status (int): The status (1=Enabled, 2=Disabled). Defaults to 1.
            description (Optional[str]): Description of the alert rule (max 100 chars).
            conditions_match_type (str): Match type for conditions ("all" or "any").
            conditions_rows (Optional[List[Dict[str, str]]]): List of condition rows,
                each with 'field' and 'value' keys. If not provided, defaults based on
                rule_type_id (e.g., allAccessRules for rule_type_id 10).
            webhook_ids (Optional[List[str]]): List of webhook IDs for notifications.
            email_recipients (Optional[List[str]]): List of email recipients.
            
        Returns:
            Optional[AlertRule]: The created or existing AlertRule model, or None on failure.
            
        Raises:
            ApiException: If the API request fails (except for 409 which is handled).
            
        Example:
            >>> client = AlertRulesClient()
            >>> rule = client.create_alert_rule(
            ...     name="Security Alert",
            ...     rule_type_id=10,
            ...     severity=1,
            ...     email_recipients=["admin@example.com"]
            ... )
        """
        api_client = self._get_api_client()
        logger.info(f"Creating new alert rule: {name}")

        # Build notification info based on provided parameters
        notification_info = []
        
        if webhook_ids:
            notification_info.append(NotificationInfoAlertRule(
                webhook_ids=webhook_ids,
                type=NotificationTypeAll("webhook"),
            ))
        
        if email_recipients:
            notification_info.append(NotificationInfoAlertRule(
                recipients=email_recipients,
                type=NotificationTypeAll("email"),
            ))

        # Build condition rows
        rows = self._build_condition_rows(conditions_rows, rule_type_id)

        # Build the request payload
        payload = CreateAlertRuleRequest(
            name=name,
            rule_type_id=rule_type_id,
            severity=SeverityAlert(severity),
            status=StatusAlertRule(status),
            description=description or "",
            conditions=ConditionsAlertRule(match_type=conditions_match_type, rows=rows),
            notification_info=notification_info,
        )

        try:
            response: CreateAlertRule201Response = api_client.create_alert_rule(
                create_alert_rule_request=payload
            )
            logger.info(f"Create response: {response.message}")
            
            # Successfully created - fetch the rule by name to get full details
            existing_rules = self.list_alert_rules()
            for rule in existing_rules:
                if rule.name == name:
                    logger.info(f"Successfully created alert rule '{name}' with ID: {rule.id}")
                    return rule
            
            logger.warning(f"Created rule '{name}' but could not find it in list")
            return None

        except ApiException as e:
            if e.status == 409:
                # Rule with same name already exists - fetch and return it
                logger.info(f"Alert rule '{name}' already exists, fetching existing rule...")
                existing_rules = self.list_alert_rules()
                for rule in existing_rules:
                    if rule.name == name:
                        logger.info(f"Found existing alert rule '{name}' with ID: {rule.id}")
                        return rule
                logger.warning(f"Could not find existing rule '{name}' after 409 response")
                return None
            logger.error(f"API error creating alert rule: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating alert rule: {e}")
            raise

    # =========================================================================
    # UPDATE ALERT RULE
    # =========================================================================
    def update_alert_rule(
        self,
        rule_id: int,
        name: str,
        rule_type_id: int,
        severity: int,
        status: int = 1,
        description: Optional[str] = None,
        conditions_match_type: str = "all",
        conditions_rows: Optional[List[Dict[str, str]]] = None,
        webhook_ids: Optional[List[str]] = None,
        email_recipients: Optional[List[str]] = None,
    ) -> Optional[AlertRule]:
        """
        Update an existing alert rule.
        
        Note: All fields must be provided as the update replaces the entire rule.
        
        Args:
            rule_id (int): The unique identifier of the alert rule to update.
            name (str): The new name of the alert rule.
            rule_type_id (int): The identifier of the rule type.
            severity (int): The severity level (1=High, 2=Medium, 3=Low).
            status (int): The status (1=Enabled, 2=Disabled). Defaults to 1.
            description (Optional[str]): Description of the alert rule.
            conditions_match_type (str): Match type for conditions.
            webhook_ids (Optional[List[str]]): List of webhook IDs for notifications.
            email_recipients (Optional[List[str]]): List of email recipients.
            
        Returns:
            Optional[AlertRule]: The updated AlertRule model, or None on failure.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = AlertRulesClient()
            >>> updated_rule = client.update_alert_rule(
            ...     rule_id=12345,
            ...     name="Updated Security Alert",
            ...     rule_type_id=10,
            ...     severity=2
            ... )
        """
        api_client = self._get_api_client()
        logger.info(f"Updating alert rule ID: {rule_id}")

        # Build notification info based on provided parameters
        notification_info = []
        
        if webhook_ids:
            notification_info.append(NotificationInfoAlertRule(
                webhook_ids=webhook_ids,
                type=NotificationTypeAll("webhook"),
            ))
        
        if email_recipients:
            notification_info.append(NotificationInfoAlertRule(
                recipients=email_recipients,
                type=NotificationTypeAll("email"),
            ))

        # Build condition rows
        rows = self._build_condition_rows(conditions_rows, rule_type_id)

        # Build the request payload
        payload = UpdateAlertRuleRequest(
            name=name,
            rule_type_id=rule_type_id,
            severity=SeverityAlert(severity),
            status=StatusAlertRule(status),
            description=description or "",
            conditions=ConditionsAlertRule(match_type=conditions_match_type, rows=rows),
            notification_info=notification_info,
        )

        try:
            response: UpdateAlertRule200Response = api_client.update_alert_rule(
                rule_id=rule_id,
                update_alert_rule_request=payload
            )
            logger.info(f"Update response: {response.message}")
            
            # Fetch the updated rule to return full details
            updated_rule = self.get_alert_rule_by_id(rule_id)
            if updated_rule:
                logger.info(f"Successfully updated alert rule ID: {rule_id}")
            return updated_rule

        except ApiException as e:
            logger.error(f"API error updating alert rule {rule_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating alert rule {rule_id}: {e}")
            raise

    # =========================================================================
    # DELETE ALERT RULES
    # =========================================================================
    def delete_alert_rules(self, rule_ids: List[int]) -> Optional[DeleteAlertRules200Response]:
        """
        Delete multiple alert rules by their IDs.
        
        Args:
            rule_ids (List[int]): List of alert rule IDs to delete (max 100).
            
        Returns:
            Optional[DeleteAlertRules200Response]: The deletion result model, or None on failure.
            
        Raises:
            ApiException: If the API request fails.
            ValueError: If rule_ids is empty or exceeds 100 items.
            
        Example:
            >>> client = AlertRulesClient()
            >>> result = client.delete_alert_rules([12345, 12346])
            >>> if result.success:
            ...     print(f"Deleted IDs: {result.successful_ids}")
        """
        if not rule_ids:
            raise ValueError("At least one rule ID must be provided")
        
        if len(rule_ids) > 100:
            raise ValueError("Cannot delete more than 100 rules at once")
        
        api_client = self._get_api_client()
        logger.info(f"Deleting {len(rule_ids)} alert rule(s): {rule_ids}")

        payload = DeleteAlertRulesRequest(rule_ids=rule_ids)

        try:
            result: DeleteAlertRules200Response = api_client.delete_alert_rules(
                delete_alert_rules_request=payload
            )
            
            if result.success:
                logger.info(f"Successfully deleted alert rules: {result.successful_ids}")
            else:
                logger.warning(f"Partial delete: successful={result.successful_ids}, errors={result.error_ids}")
            
            return result

        except ApiException as e:
            logger.error(f"API error deleting alert rules: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error deleting alert rules: {e}")
            raise

    # =========================================================================
    # UPDATE ALERT RULES STATUS
    # =========================================================================
    def update_alert_rules_status(
        self, 
        rule_ids: List[int], 
        status: int
    ) -> Optional[UpdateAlertRulesStatus200Response]:
        """
        Update the status of multiple alert rules.
        
        Args:
            rule_ids (List[int]): List of alert rule IDs to update (1-100 items).
            status (int): The new status (1=Enabled, 2=Disabled).
            
        Returns:
            Optional[UpdateAlertRulesStatus200Response]: The update result model, or None on failure.
            
        Raises:
            ApiException: If the API request fails.
            ValueError: If rule_ids is empty, exceeds 100 items, or status is invalid.
            
        Example:
            >>> client = AlertRulesClient()
            >>> # Disable alert rules
            >>> result = client.update_alert_rules_status([12345, 12346], status=2)
            >>> # Enable alert rules
            >>> result = client.update_alert_rules_status([12345], status=1)
        """
        if not rule_ids:
            raise ValueError("At least one rule ID must be provided")
        
        if len(rule_ids) > 100:
            raise ValueError("Cannot update more than 100 rules at once")
        
        if status not in [1, 2]:
            raise ValueError("Status must be 1 (Enabled) or 2 (Disabled)")
        
        api_client = self._get_api_client()
        status_text = "Enabled" if status == 1 else "Disabled"
        logger.info(f"Updating status to '{status_text}' for {len(rule_ids)} rule(s): {rule_ids}")

        payload = UpdateAlertRulesStatusRequest(
            entity_ids=rule_ids,
            status=status
        )

        try:
            result: UpdateAlertRulesStatus200Response = api_client.update_alert_rules_status(
                update_alert_rules_status_request=payload
            )
            
            if result.success:
                logger.info(f"Successfully updated status for alert rules: {result.successful_ids}")
            else:
                logger.warning(f"Partial update: successful={result.successful_ids}, errors={result.error_ids}")
            
            return result

        except ApiException as e:
            logger.error(f"API error updating alert rules status: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating alert rules status: {e}")
            raise

    def enable_alert_rules(self, rule_ids: List[int]) -> Optional[UpdateAlertRulesStatus200Response]:
        """
        Enable multiple alert rules.
        
        Convenience method that calls update_alert_rules_status with status=1.
        
        Args:
            rule_ids (List[int]): List of alert rule IDs to enable.
            
        Returns:
            Optional[UpdateAlertRulesStatus200Response]: The update result, or None on failure.
            
        Example:
            >>> client = AlertRulesClient()
            >>> result = client.enable_alert_rules([12345, 12346])
        """
        return self.update_alert_rules_status(rule_ids, status=1)

    def disable_alert_rules(self, rule_ids: List[int]) -> Optional[UpdateAlertRulesStatus200Response]:
        """
        Disable multiple alert rules.
        
        Convenience method that calls update_alert_rules_status with status=2.
        
        Args:
            rule_ids (List[int]): List of alert rule IDs to disable.
            
        Returns:
            Optional[UpdateAlertRulesStatus200Response]: The update result, or None on failure.
            
        Example:
            >>> client = AlertRulesClient()
            >>> result = client.disable_alert_rules([12345, 12346])
        """
        return self.update_alert_rules_status(rule_ids, status=2)


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================
def setup_argparse() -> argparse.ArgumentParser:
    """
    Set up the argument parser for the CLI.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Cisco Secure Access Alert Rules Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all alert rules
  python alert_rules.py list

  # Get a specific alert rule
  python alert_rules.py get --id 12345

  # Create a new alert rule (uses default conditions for rule type 10)
  python alert_rules.py create --name "My Alert Rule" --rule-type-id 10 --severity 1

  # Create with email notifications
  python alert_rules.py create --name "Email Alert" --rule-type-id 10 --severity 1 \\
      --email admin@example.com security@example.com

  # Create with specific access rules (comma-separated rule IDs)
  python alert_rules.py create --name "Specific Rules Alert" --rule-type-id 10 --severity 2 \\
      --conditions "specificAccessRules=1261863,1260333,1260344"

  # Create with webhook notifications
  python alert_rules.py create --name "Webhook Alert" --rule-type-id 10 --severity 2 \\
      --webhook-ids webhook.v1:abc123

  # Update an existing alert rule
  python alert_rules.py update --id 12345 --name "Updated Name" --rule-type-id 10 --severity 2

  # Update with specific conditions
  python alert_rules.py update --id 12345 --name "Updated" --rule-type-id 10 --severity 2 \\
      --conditions allAccessRules=

  # Delete alert rules
  python alert_rules.py delete --ids 12345 12346

  # Enable alert rules
  python alert_rules.py update-status --ids 12345 12346 --status 1

  # Disable alert rules
  python alert_rules.py update-status --ids 12345 --status 2

Condition Defaults (when --conditions is not specified):
  Rule Type 10 (Access Rule Changes): allAccessRules=
  Other rule types:                    allAccessRules=

Note: Connectivity alerts (rule_type_id 1-2) require an 'operator' field in
  conditions which is not supported by the current SDK. Use the UI for those.

API Documentation:
  https://developer.cisco.com/docs/cloud-security/list-alert-rules/
  https://developer.cisco.com/docs/cloud-security/get-alert-rule/
  https://developer.cisco.com/docs/cloud-security/create-alert-rule/
  https://developer.cisco.com/docs/cloud-security/update-alert-rule/
  https://developer.cisco.com/docs/cloud-security/delete-alert-rules/
  https://developer.cisco.com/docs/cloud-security/update-status-of-alert-rules/
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # List command
    list_parser = subparsers.add_parser(
        "list",
        help="List all alert rules",
        description="Retrieve and display all alert rules for the organization."
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # Get command
    get_parser = subparsers.add_parser(
        "get",
        help="Get a specific alert rule by ID",
        description="Retrieve details of a specific alert rule."
    )
    get_parser.add_argument(
        "--id",
        type=int,
        required=True,
        help="The unique ID of the alert rule"
    )
    get_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # Create command
    create_parser = subparsers.add_parser(
        "create",
        help="Create a new alert rule",
        description="Create a new alert rule with the specified configuration."
    )
    create_parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Name of the alert rule (max 255 characters)"
    )
    create_parser.add_argument(
        "--rule-type-id",
        type=int,
        required=True,
        help="Rule type identifier"
    )
    create_parser.add_argument(
        "--severity",
        type=int,
        choices=[1, 2, 3],
        required=True,
        help="Severity level: 1=High, 2=Medium, 3=Low"
    )
    create_parser.add_argument(
        "--status",
        type=int,
        choices=[1, 2],
        default=1,
        help="Status: 1=Enabled (default), 2=Disabled"
    )
    create_parser.add_argument(
        "--description",
        type=str,
        help="Description of the alert rule (max 100 characters)"
    )
    create_parser.add_argument(
        "--conditions-match-type",
        type=str,
        choices=["all", "any"],
        default="all",
        help="Conditions match type: 'all' (default) or 'any'"
    )
    create_parser.add_argument(
        "--conditions",
        type=str,
        nargs="+",
        metavar="FIELD=VALUE",
        help="Condition rows as field=value pairs (e.g., allAccessRules= or tunnelGroupName=myTunnel). "
             "If not specified, a default is applied based on --rule-type-id."
    )
    create_parser.add_argument(
        "--webhook-ids",
        type=str,
        nargs="+",
        help="Webhook IDs for notifications"
    )
    create_parser.add_argument(
        "--email",
        type=str,
        nargs="+",
        dest="email_recipients",
        help="Email recipients for notifications"
    )
    create_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # Update command
    update_parser = subparsers.add_parser(
        "update",
        help="Update an existing alert rule",
        description="Update an existing alert rule. All fields must be provided."
    )
    update_parser.add_argument(
        "--id",
        type=int,
        required=True,
        help="The unique ID of the alert rule to update"
    )
    update_parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="New name of the alert rule"
    )
    update_parser.add_argument(
        "--rule-type-id",
        type=int,
        required=True,
        help="Rule type identifier"
    )
    update_parser.add_argument(
        "--severity",
        type=int,
        choices=[1, 2, 3],
        required=True,
        help="Severity level: 1=High, 2=Medium, 3=Low"
    )
    update_parser.add_argument(
        "--status",
        type=int,
        choices=[1, 2],
        default=1,
        help="Status: 1=Enabled (default), 2=Disabled"
    )
    update_parser.add_argument(
        "--description",
        type=str,
        help="Description of the alert rule (max 100 characters)"
    )
    update_parser.add_argument(
        "--conditions-match-type",
        type=str,
        choices=["all", "any"],
        default="all",
        help="Conditions match type: 'all' (default) or 'any'"
    )
    update_parser.add_argument(
        "--conditions",
        type=str,
        nargs="+",
        metavar="FIELD=VALUE",
        help="Condition rows as field=value pairs (e.g., allAccessRules= or tunnelGroupName=myTunnel). "
             "If not specified, a default is applied based on --rule-type-id."
    )
    update_parser.add_argument(
        "--webhook-ids",
        type=str,
        nargs="+",
        help="Webhook IDs for notifications"
    )
    update_parser.add_argument(
        "--email",
        type=str,
        nargs="+",
        dest="email_recipients",
        help="Email recipients for notifications"
    )
    update_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # Delete command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete alert rules",
        description="Delete one or more alert rules by their IDs."
    )
    delete_parser.add_argument(
        "--ids",
        type=int,
        nargs="+",
        required=True,
        help="IDs of the alert rules to delete (max 100)"
    )
    delete_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # Update status command
    status_parser = subparsers.add_parser(
        "update-status",
        help="Update the status of alert rules",
        description="Enable or disable one or more alert rules."
    )
    status_parser.add_argument(
        "--ids",
        type=int,
        nargs="+",
        required=True,
        help="IDs of the alert rules to update (max 100)"
    )
    status_parser.add_argument(
        "--status",
        type=int,
        choices=[1, 2],
        required=True,
        help="New status: 1=Enabled, 2=Disabled"
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    return parser


def print_result(data: Any, as_json: bool = False) -> None:
    """
    Print the result data in the specified format.
    
    Args:
        data: The data to print (can be SDK models, dicts, or lists).
        as_json: If True, output as JSON; otherwise, print normally.
    """
    # Convert SDK models to dicts for serialization
    def to_serializable(obj):
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif isinstance(obj, list):
            return [to_serializable(item) for item in obj]
        return obj
    
    serializable_data = to_serializable(data)
    
    if as_json:
        print(json.dumps(serializable_data, indent=2, default=str))
    else:
        if isinstance(serializable_data, list):
            for item in serializable_data:
                print("-" * 60)
                if isinstance(item, dict):
                    for key, value in item.items():
                        print(f"  {key}: {value}")
                else:
                    print(f"  {item}")
            print("-" * 60)
        elif isinstance(serializable_data, dict):
            for key, value in serializable_data.items():
                print(f"  {key}: {value}")
        else:
            print(serializable_data)


def parse_conditions(conditions: Optional[List[str]]) -> Optional[List[Dict[str, str]]]:
    """
    Parse condition strings from CLI into list of dicts.
    
    Each condition is in the format 'field=value' (value can be empty).
    
    Args:
        conditions: List of 'field=value' strings, or None.
        
    Returns:
        List of dicts with 'field' and 'value' keys, or None.
    """
    if not conditions:
        return None
    rows = []
    for cond in conditions:
        if "=" in cond:
            field, value = cond.split("=", 1)
            rows.append({"field": field, "value": value})
        else:
            rows.append({"field": cond, "value": ""})
    return rows


def main() -> int:
    """
    Main entry point for the CLI.
    
    Returns:
        int: Exit code (0 for success, 1 for failure).
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        client = AlertRulesClient()

        if args.command == "list":
            rules = client.list_alert_rules()
            print(f"\nFound {len(rules)} alert rule(s):\n")
            print_result(rules, args.json)

        elif args.command == "get":
            rule = client.get_alert_rule_by_id(args.id)
            if rule:
                print(f"\nAlert Rule Details:\n")
                print_result(rule, args.json)
            else:
                print(f"Alert rule with ID {args.id} not found.")
                return 1

        elif args.command == "create":
            conditions_rows = parse_conditions(getattr(args, 'conditions', None))
            rule = client.create_alert_rule(
                name=args.name,
                rule_type_id=args.rule_type_id,
                severity=args.severity,
                status=args.status,
                description=args.description,
                conditions_match_type=args.conditions_match_type,
                conditions_rows=conditions_rows,
                webhook_ids=args.webhook_ids,
                email_recipients=args.email_recipients,
            )
            
            if rule:
                print(f"\nAlert Rule:\n")
                print_result(rule, args.json)
            else:
                print("Failed to create alert rule.")
                return 1

        elif args.command == "update":
            conditions_rows = parse_conditions(getattr(args, 'conditions', None))
            rule = client.update_alert_rule(
                rule_id=args.id,
                name=args.name,
                rule_type_id=args.rule_type_id,
                severity=args.severity,
                status=args.status,
                description=args.description,
                conditions_match_type=args.conditions_match_type,
                conditions_rows=conditions_rows,
                webhook_ids=args.webhook_ids,
                email_recipients=args.email_recipients,
            )
            
            if rule:
                print(f"\nAlert Rule Updated:\n")
                print_result(rule, args.json)
            else:
                print(f"Failed to update alert rule with ID {args.id}.")
                return 1

        elif args.command == "delete":
            result = client.delete_alert_rules(args.ids)
            if result:
                print(f"\nDeletion Result:\n")
                print_result(result, args.json)
            else:
                print(f"Failed to delete alert rules: {args.ids}")
                return 1

        elif args.command == "update-status":
            result = client.update_alert_rules_status(args.ids, args.status)
            status_text = "Enabled" if args.status == 1 else "Disabled"
            if result:
                print(f"\nStatus Update Result ({status_text}):\n")
                print_result(result, args.json)
            else:
                print(f"Failed to update status for alert rules: {args.ids}")
                return 1

        return 0

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return 1
    except ApiException as e:
        logger.error(f"API error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
