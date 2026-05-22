# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
DLP Rule Events Management Example for Cisco Secure Access API.

This module provides a comprehensive example of retrieving DLP rule events using
the Cisco Secure Access Python SDK. It demonstrates read operations for:
- List Real-Time DLP rule events
- List SaaS API DLP rule events
- List AI Guardrails DLP rule events
- Get DLP event details by ID

Usage:
    python dlp_rule_events.py list-realtime --from="-1days" --to="now"
    python dlp_rule_events.py list-saas --from="-7days" --to="now" --severity WARNING
    python dlp_rule_events.py list-ai-guardrails --from="-1days" --to="now"
    python dlp_rule_events.py get --event-type realTime --id <event_id>
    python dlp_rule_events.py --region eu list-realtime --from="-1days" --to="now"

Note: Use --from="value" syntax (with =) for negative values like "-1days"

API Base URLs (DLP Events uses regional endpoints):
    - US (default): https://api.sse.cisco.com/reports.us/v2
    - EU: https://api.sse.cisco.com/reports.eu/v2

Requirements:
    - Set CLIENT_ID and CLIENT_SECRET environment variables
    - Ensure all dependencies in requirements.txt are installed

API Documentation:
    - https://developer.cisco.com/docs/cloud-security/list-real-time-dlp-rule-events/
    - https://developer.cisco.com/docs/cloud-security/list-saas-api-dlp-rule-events/
    - https://developer.cisco.com/docs/cloud-security/list-ai-guardrails-dlp-rule-events/
    - https://developer.cisco.com/docs/cloud-security/get-dlp-event-details/
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional

from access_token import get_valid_access_token
from secure_access.api.dlp_rule_events_api import DLPRuleEventsApi
from secure_access.exceptions import ApiException

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Valid values for filter parameters
VALID_ACTIONS = ["block", "delete", "monitor", "quarantine", "revoke_sharing"]
VALID_SEVERITIES = ["INFO", "WARNING", "CRITICAL"]
VALID_EXPOSURES = ["PUBLIC", "INTERNAL", "EXTERNAL"]
VALID_EVENT_TYPES = ["realTime", "saasApi", "aiGuardrails"]
VALID_REGIONS = ["us", "eu"]

# DLP Events API uses a different base URL with region
# DLP_REPORTS_BASE_URL = "https://api.sse.cisco.com/reports.{region}/v2"
DLP_REPORTS_BASE_URL = "https://api.umbrella.com/reports.{region}/v2"


class DLPRuleEventsClient:
    """
    Client for retrieving Cisco Secure Access DLP Rule Events.
    
    Provides methods for querying DLP events including:
    - Listing Real-Time DLP rule events
    - Listing SaaS API DLP rule events
    - Listing AI Guardrails DLP rule events
    - Getting specific DLP event details by ID
    
    Note: DLP Events API uses a regional endpoint:
    - US: https://api.sse.cisco.com/reports.us/v2
    - EU: https://api.sse.cisco.com/reports.eu/v2
    """

    def __init__(self, region: str = "us") -> None:
        """
        Initialize the DLPRuleEventsClient with authentication.
        
        Args:
            region (str): The region for the DLP events API. 
                         Valid values: 'us' (default), 'eu'
        
        Raises:
            ValueError: If region is invalid or environment variables are not set.
            Exception: If access token generation fails.
        """
        if region not in VALID_REGIONS:
            raise ValueError(f"Invalid region '{region}'. Must be one of: {', '.join(VALID_REGIONS)}")
        
        self.region = region
        self.base_url = DLP_REPORTS_BASE_URL.format(region=region)
        
        try:
            self.access_token = get_valid_access_token()
            logger.info(f"Successfully obtained access token (region: {region})")
        except Exception as e:
            logger.error(f"Failed to obtain access token: {e}")
            raise

    def _get_api_client(self) -> DLPRuleEventsApi:
        """
        Create and configure a DLPRuleEventsApi client with authorization header.
        
        Returns:
            DLPRuleEventsApi: Configured API client instance.
        """
        from secure_access.configuration import Configuration
        from secure_access.api_client import ApiClient
        
        # Configure with the regional reports URL
        configuration = Configuration(host=self.base_url, access_token=self.access_token)
        client = ApiClient(configuration=configuration)
        
        api_client = DLPRuleEventsApi(api_client=client)
        return api_client

    # =========================================================================
    # LIST REAL-TIME DLP RULE EVENTS
    # =========================================================================
    def list_realtime_events(
        self,
        var_from: str,
        to: str,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        identity_type: Optional[str] = None,
        application_id: Optional[int] = None,
        application_category_id: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        List Real-Time DLP rule events.
        
        Get the Real-Time DLP rule events triggered by rules applied to 
        private or internet resources.
        
        Uses the without_preload_content variant to bypass SDK model validation,
        which may reject valid API responses with newer enum values.
        
        Args:
            var_from (str): Timestamp or relative time string (e.g., '-1days').
                           Filters for data after this time.
            to (str): Timestamp or relative time string (e.g., 'now').
                     Filters for data before this time.
            action (Optional[str]): Filter by action (blocked, deleted, 
                                   monitored, quarantined, restored, revoked).
            severity (Optional[str]): Filter by severity (INFO, WARNING, CRITICAL).
            identity_type (Optional[str]): Filter by identity type 
                                          (e.g., directory_user, directory_group).
            application_id (Optional[int]): Filter by application ID.
            application_category_id (Optional[int]): Filter by application category ID.
            limit (Optional[int]): Maximum number of events to return (default: 50).
            offset (Optional[int]): Index offset for pagination (default: 0).
            
        Returns:
            Dict[str, Any]: List of Real-Time DLP rule events as raw dict.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = DLPRuleEventsClient()
            >>> events = client.list_realtime_events(
            ...     var_from="-1days",
            ...     to="now",
            ...     severity="CRITICAL"
            ... )
            >>> for event in events.get("events", []):
            ...     print(f"Event: {event['eventId']}")
        """
        api_client = self._get_api_client()
        logger.info(f"Retrieving Real-Time DLP events from '{var_from}' to '{to}'...")

        try:
            response = api_client.get_all_real_time_events_without_preload_content(
                var_from=var_from,
                to=to,
                action=action,
                severity=severity,
                identity_type=identity_type,
                application_id=application_id,
                application_category_id=application_category_id,
                limit=limit,
                offset=offset,
            )
            events = json.loads(response.data)
            event_count = len(events.get("events", []))
            logger.info(f"Successfully retrieved {event_count} Real-Time DLP events")
            return events

        except ApiException as e:
            logger.error(f"API error listing Real-Time DLP events: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing Real-Time DLP events: {e}")
            raise

    # =========================================================================
    # LIST SAAS API DLP RULE EVENTS
    # =========================================================================
    def list_saas_api_events(
        self,
        var_from: str,
        to: str,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        identity_type: Optional[str] = None,
        application_id: Optional[int] = None,
        application_category_id: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        exposure: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List SaaS API DLP rule events.
        
        Get SaaS API DLP rule events triggered by rules applied to SaaS applications.
        
        Uses the without_preload_content variant to bypass SDK model validation.
        
        Args:
            var_from (str): Timestamp or relative time string (e.g., '-1days').
                           Filters for data after this time.
            to (str): Timestamp or relative time string (e.g., 'now').
                     Filters for data before this time.
            action (Optional[str]): Filter by action (blocked, deleted, 
                                   monitored, quarantined, restored, revoked).
            severity (Optional[str]): Filter by severity (INFO, WARNING, CRITICAL).
            identity_type (Optional[str]): Filter by identity type 
                                          (e.g., directory_user, directory_group).
            application_id (Optional[int]): Filter by application ID.
            application_category_id (Optional[int]): Filter by application category ID.
            limit (Optional[int]): Maximum number of events to return (default: 50).
            offset (Optional[int]): Index offset for pagination (default: 0).
            exposure (Optional[str]): Filter by exposure level (PUBLIC, INTERNAL, EXTERNAL).
            
        Returns:
            Dict[str, Any]: List of SaaS API DLP rule events as raw dict.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = DLPRuleEventsClient()
            >>> events = client.list_saas_api_events(
            ...     var_from="-7days",
            ...     to="now",
            ...     exposure="EXTERNAL"
            ... )
        """
        api_client = self._get_api_client()
        logger.info(f"Retrieving SaaS API DLP events from '{var_from}' to '{to}'...")

        try:
            response = api_client.get_all_saa_sapi_events_without_preload_content(
                var_from=var_from,
                to=to,
                action=action,
                severity=severity,
                identity_type=identity_type,
                application_id=application_id,
                application_category_id=application_category_id,
                limit=limit,
                offset=offset,
                exposure=exposure,
            )
            events = json.loads(response.data)
            event_count = len(events.get("events", []))
            logger.info(f"Successfully retrieved {event_count} SaaS API DLP events")
            return events

        except ApiException as e:
            logger.error(f"API error listing SaaS API DLP events: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing SaaS API DLP events: {e}")
            raise

    # =========================================================================
    # LIST AI GUARDRAILS DLP RULE EVENTS
    # =========================================================================
    def list_ai_guardrails_events(
        self,
        var_from: str,
        to: str,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        identity_type: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        List AI Guardrails DLP rule events.
        
        Get the AI Guardrails DLP rule events triggered by rules applied 
        to AI Guardrails use cases.
        
        Uses the without_preload_content variant to bypass SDK model validation.
        
        Args:
            var_from (str): Timestamp or relative time string (e.g., '-1days').
                           Filters for data after this time.
            to (str): Timestamp or relative time string (e.g., 'now').
                     Filters for data before this time.
            action (Optional[str]): Filter by action (blocked, deleted, 
                                   monitored, quarantined, restored, revoked).
            severity (Optional[str]): Filter by severity (INFO, WARNING, CRITICAL).
            identity_type (Optional[str]): Filter by identity type 
                                          (e.g., directory_user, directory_group).
            limit (Optional[int]): Maximum number of events to return (default: 50).
            offset (Optional[int]): Index offset for pagination (default: 0).
            
        Returns:
            Dict[str, Any]: List of AI Guardrails DLP rule events as raw dict.
            
        Raises:
            ApiException: If the API request fails.
            
        Example:
            >>> client = DLPRuleEventsClient()
            >>> events = client.list_ai_guardrails_events(
            ...     var_from="-1days",
            ...     to="now"
            ... )
        """
        api_client = self._get_api_client()
        logger.info(f"Retrieving AI Guardrails DLP events from '{var_from}' to '{to}'...")

        try:
            response = api_client.get_all_ai_guardrails_events_without_preload_content(
                var_from=var_from,
                to=to,
                action=action,
                severity=severity,
                identity_type=identity_type,
                limit=limit,
                offset=offset,
            )
            events = json.loads(response.data)
            event_count = len(events.get("events", []))
            logger.info(f"Successfully retrieved {event_count} AI Guardrails DLP events")
            return events

        except ApiException as e:
            logger.error(f"API error listing AI Guardrails DLP events: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing AI Guardrails DLP events: {e}")
            raise

    # =========================================================================
    # GET DLP EVENT DETAILS BY ID
    # =========================================================================
    def get_event_details(
        self,
        event_type: str,
        event_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific DLP event by its ID.
        
        Uses the without_preload_content variant to bypass SDK model validation.
        
        Args:
            event_type (str): The type of event. Valid values:
                             - 'realTime' for Real-Time events
                             - 'saasApi' for SaaS API events
                             - 'aiGuardrails' for AI Guardrails events
            event_id (str): The unique identifier of the event.
            
        Returns:
            Optional[Dict[str, Any]]: The DLP event details as raw dict, or None if not found.
            
        Raises:
            ApiException: If the API request fails.
            ValueError: If event_type is not valid.
            
        Example:
            >>> client = DLPRuleEventsClient()
            >>> event = client.get_event_details(
            ...     event_type="realTime",
            ...     event_id="a1764e27-9e48-4dc4-8e93-e315472d42ed"
            ... )
            >>> if event:
            ...     print(f"Event action: {event['action']}")
        """
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. "
                f"Must be one of: {', '.join(VALID_EVENT_TYPES)}"
            )

        api_client = self._get_api_client()
        logger.info(f"Retrieving {event_type} DLP event with ID: {event_id}")

        try:
            response = api_client.get_dlp_event_details_by_id_without_preload_content(
                event_type=event_type,
                id=event_id,
            )
            event = json.loads(response.data)
            logger.info(f"Successfully retrieved DLP event details for ID: {event_id}")
            return event

        except ApiException as e:
            if e.status == 404:
                logger.warning(f"DLP event {event_id} not found")
                return None
            logger.error(f"API error getting DLP event {event_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting DLP event {event_id}: {e}")
            raise


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
        description="Cisco Secure Access DLP Rule Events Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List Real-Time DLP events from the last day
  python dlp_rule_events.py list-realtime --from="-1days" --to="now"

  # List Real-Time DLP events with filters
  python dlp_rule_events.py list-realtime --from="-7days" --to="now" \\
      --severity CRITICAL --action block --limit 10

  # List SaaS API DLP events with exposure filter
  python dlp_rule_events.py list-saas --from="-1days" --to="now" \\
      --exposure EXTERNAL

  # List AI Guardrails DLP events
  python dlp_rule_events.py list-ai-guardrails --from="-1days" --to="now"

  # Use EU region
  python dlp_rule_events.py --region eu list-realtime --from="-1days" --to="now"

  # Get specific event details
  python dlp_rule_events.py get --event-type realTime \\
      --id "a1764e27-9e48-4dc4-8e93-e315472d42ed"

  # Output as JSON for scripting
  python dlp_rule_events.py list-realtime --from="-1days" --to="now" --json

Time Range Parameters:
  - Use relative times like "-1days", "-7days", "-1hours"
  - Use "now" for the current time
  - Use Unix timestamps in milliseconds (e.g., "1639146300000")
  - IMPORTANT: Use --from="-1days" syntax (with =) for negative values

Region:
  - US (default): https://api.sse.cisco.com/reports.us/v2
  - EU: https://api.sse.cisco.com/reports.eu/v2

API Documentation:
  https://developer.cisco.com/docs/cloud-security/list-real-time-dlp-rule-events/
  https://developer.cisco.com/docs/cloud-security/list-saas-api-dlp-rule-events/
  https://developer.cisco.com/docs/cloud-security/list-ai-guardrails-dlp-rule-events/
  https://developer.cisco.com/docs/cloud-security/get-dlp-event-details/
"""
    )

    # Global argument for region
    parser.add_argument(
        "--region",
        type=str,
        choices=VALID_REGIONS,
        default="us",
        help="API region: 'us' (default) or 'eu'"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # =========================================================================
    # List Real-Time Events command
    # =========================================================================
    realtime_parser = subparsers.add_parser(
        "list-realtime",
        help="List Real-Time DLP rule events",
        description="Get Real-Time DLP events triggered by rules applied to private or internet resources."
    )
    realtime_parser.add_argument(
        "--from",
        dest="var_from",
        type=str,
        required=True,
        help="Start time: timestamp or relative time (e.g., '-1days', '-7days')"
    )
    realtime_parser.add_argument(
        "--to",
        type=str,
        required=True,
        help="End time: timestamp or relative time (e.g., 'now')"
    )
    realtime_parser.add_argument(
        "--action",
        type=str,
        choices=VALID_ACTIONS,
        help=f"Filter by action: {', '.join(VALID_ACTIONS)}"
    )
    realtime_parser.add_argument(
        "--severity",
        type=str,
        choices=VALID_SEVERITIES,
        help=f"Filter by severity: {', '.join(VALID_SEVERITIES)}"
    )
    realtime_parser.add_argument(
        "--identity-type",
        type=str,
        help="Filter by identity type (e.g., directory_user, directory_group, network)"
    )
    realtime_parser.add_argument(
        "--application-id",
        type=int,
        help="Filter by application ID"
    )
    realtime_parser.add_argument(
        "--application-category-id",
        type=int,
        help="Filter by application category ID"
    )
    realtime_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of events to return (default: 50)"
    )
    realtime_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Index offset for pagination (default: 0)"
    )
    realtime_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # =========================================================================
    # List SaaS API Events command
    # =========================================================================
    saas_parser = subparsers.add_parser(
        "list-saas",
        help="List SaaS API DLP rule events",
        description="Get SaaS API DLP events triggered by rules applied to SaaS applications."
    )
    saas_parser.add_argument(
        "--from",
        dest="var_from",
        type=str,
        required=True,
        help="Start time: timestamp or relative time (e.g., '-1days', '-7days')"
    )
    saas_parser.add_argument(
        "--to",
        type=str,
        required=True,
        help="End time: timestamp or relative time (e.g., 'now')"
    )
    saas_parser.add_argument(
        "--action",
        type=str,
        choices=VALID_ACTIONS,
        help=f"Filter by action: {', '.join(VALID_ACTIONS)}"
    )
    saas_parser.add_argument(
        "--severity",
        type=str,
        choices=VALID_SEVERITIES,
        help=f"Filter by severity: {', '.join(VALID_SEVERITIES)}"
    )
    saas_parser.add_argument(
        "--identity-type",
        type=str,
        help="Filter by identity type (e.g., directory_user, directory_group, network)"
    )
    saas_parser.add_argument(
        "--application-id",
        type=int,
        help="Filter by application ID"
    )
    saas_parser.add_argument(
        "--application-category-id",
        type=int,
        help="Filter by application category ID"
    )
    saas_parser.add_argument(
        "--exposure",
        type=str,
        choices=VALID_EXPOSURES,
        help=f"Filter by exposure level: {', '.join(VALID_EXPOSURES)}"
    )
    saas_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of events to return (default: 50)"
    )
    saas_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Index offset for pagination (default: 0)"
    )
    saas_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # =========================================================================
    # List AI Guardrails Events command
    # =========================================================================
    ai_parser = subparsers.add_parser(
        "list-ai-guardrails",
        help="List AI Guardrails DLP rule events",
        description="Get AI Guardrails DLP events triggered by rules applied to AI Guardrails use cases."
    )
    ai_parser.add_argument(
        "--from",
        dest="var_from",
        type=str,
        required=True,
        help="Start time: timestamp or relative time (e.g., '-1days', '-7days')"
    )
    ai_parser.add_argument(
        "--to",
        type=str,
        required=True,
        help="End time: timestamp or relative time (e.g., 'now')"
    )
    ai_parser.add_argument(
        "--action",
        type=str,
        choices=VALID_ACTIONS,
        help=f"Filter by action: {', '.join(VALID_ACTIONS)}"
    )
    ai_parser.add_argument(
        "--severity",
        type=str,
        choices=VALID_SEVERITIES,
        help=f"Filter by severity: {', '.join(VALID_SEVERITIES)}"
    )
    ai_parser.add_argument(
        "--identity-type",
        type=str,
        help="Filter by identity type (e.g., directory_user, directory_group, network)"
    )
    ai_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of events to return (default: 50)"
    )
    ai_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Index offset for pagination (default: 0)"
    )
    ai_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # =========================================================================
    # Get Event Details command
    # =========================================================================
    get_parser = subparsers.add_parser(
        "get",
        help="Get DLP event details by ID",
        description="Get detailed information about a specific DLP event."
    )
    get_parser.add_argument(
        "--event-type",
        type=str,
        required=True,
        choices=VALID_EVENT_TYPES,
        help=f"Event type: {', '.join(VALID_EVENT_TYPES)}"
    )
    get_parser.add_argument(
        "--id",
        type=str,
        required=True,
        help="The unique identifier of the event"
    )
    get_parser.add_argument(
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
        if isinstance(serializable_data, dict):
            # Handle the events wrapper
            if 'events' in serializable_data:
                events = serializable_data['events']
                if events:
                    for item in events:
                        print("-" * 80)
                        if isinstance(item, dict):
                            for key, value in item.items():
                                print(f"  {key}: {value}")
                        else:
                            print(f"  {item}")
                    print("-" * 80)
                else:
                    print("No events found.")
            else:
                # Single event details
                for key, value in serializable_data.items():
                    print(f"  {key}: {value}")
        elif isinstance(serializable_data, list):
            for item in serializable_data:
                print("-" * 80)
                if isinstance(item, dict):
                    for key, value in item.items():
                        print(f"  {key}: {value}")
                else:
                    print(f"  {item}")
            print("-" * 80)
        else:
            print(serializable_data)


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
        client = DLPRuleEventsClient(region=args.region)

        if args.command == "list-realtime":
            events = client.list_realtime_events(
                var_from=args.var_from,
                to=args.to,
                action=args.action,
                severity=args.severity,
                identity_type=args.identity_type,
                application_id=args.application_id,
                application_category_id=args.application_category_id,
                limit=args.limit,
                offset=args.offset,
            )
            event_count = len(events.get("events", []))
            print(f"\nFound {event_count} Real-Time DLP event(s):\n")
            print_result(events, args.json)

        elif args.command == "list-saas":
            events = client.list_saas_api_events(
                var_from=args.var_from,
                to=args.to,
                action=args.action,
                severity=args.severity,
                identity_type=args.identity_type,
                application_id=args.application_id,
                application_category_id=args.application_category_id,
                limit=args.limit,
                offset=args.offset,
                exposure=args.exposure,
            )
            event_count = len(events.get("events", []))
            print(f"\nFound {event_count} SaaS API DLP event(s):\n")
            print_result(events, args.json)

        elif args.command == "list-ai-guardrails":
            events = client.list_ai_guardrails_events(
                var_from=args.var_from,
                to=args.to,
                action=args.action,
                severity=args.severity,
                identity_type=args.identity_type,
                limit=args.limit,
                offset=args.offset,
            )
            event_count = len(events.get("events", []))
            print(f"\nFound {event_count} AI Guardrails DLP event(s):\n")
            print_result(events, args.json)

        elif args.command == "get":
            event = client.get_event_details(
                event_type=args.event_type,
                event_id=args.id,
            )
            if event:
                print(f"\nDLP Event Details ({args.event_type}):\n")
                print_result(event, args.json)
            else:
                print(f"DLP event with ID '{args.id}' not found.")
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
