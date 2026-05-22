# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Cisco Secure Access API Client - Class-based implementation with idempotent operations.

This module provides a class-based wrapper around the Cisco Secure Access API,
handling authentication, resource creation with idempotency checks, and proper logging.

Usage:
    # Run all operations (create destination list, network tunnel groups, private resources, and access policy)
    python complex_example.py --operation all

    # Create only destination list
    python complex_example.py --operation destination-list

    # Create only network tunnel groups
    python complex_example.py --operation network-tunnel-groups

    # Create only private resources
    python complex_example.py --operation private-resources

    # Create access policy (requires existing network tunnel group and private resource IDs)
    python complex_example.py --operation access-policy --ntg-id <network_tunnel_group_id> --pr-id <private_resource_id>

    # List existing network tunnel groups (without creating)
    python complex_example.py --operation list-network-tunnel-groups

    # List existing private resources (without creating)
    python complex_example.py --operation list-private-resources

    # Get identities
    python complex_example.py --operation identities

    # Enable verbose logging
    python complex_example.py --operation all --verbose
"""

import argparse
import logging
import sys
from typing import Any, List, Tuple, Optional

from access_token import get_valid_access_token
from secure_access.api.destination_lists_api import DestinationListsApi
from secure_access.models.destination_list_create import DestinationListCreate
from secure_access.models.destination_list_create_destinations_inner import DestinationListCreateDestinationsInner
from secure_access.models.add_network_tunnel_group_request import AddNetworkTunnelGroupRequest
from secure_access.models.add_network_tunnel_group_request_auth_id_prefix import AddNetworkTunnelGroupRequestAuthIdPrefix
from secure_access.models.device_type import DeviceType
from secure_access.models.routing_request_data import RoutingRequestData
from secure_access.models.static_data_request_obj import StaticDataRequestObj
from secure_access.api.network_tunnel_groups_api import NetworkTunnelGroupsApi
from secure_access.models.routing_request import RoutingRequest
from secure_access.models.private_resource_request import PrivateResourceRequest
from secure_access.models.access_types_request_inner import AccessTypesRequestInner
from secure_access.models.network_based_access import NetworkBasedAccess
from secure_access.models.resource_addresses_inner import ResourceAddressesInner
from secure_access.models.resource_addresses_inner_protocol_ports_inner import ResourceAddressesInnerProtocolPortsInner
from secure_access.api.private_resources_api import PrivateResourcesApi
from secure_access.models.client_based_access import ClientBasedAccess
from secure_access.models.add_rule_request import AddRuleRequest
from secure_access.models.rule_action import RuleAction
from secure_access.models.rule_settings_inner import RuleSettingsInner
from secure_access.models.rule_conditions_inner import RuleConditionsInner
from secure_access.api.access_rules_api import AccessRulesApi
from secure_access.api.identities_api import IdentitiesApi
from secure_access.models.access import Access
from secure_access.models.attribute_name import AttributeName
from secure_access.models.attribute_value import AttributeValue
from secure_access.models.setting_value import SettingValue


# Logger instance (configured in setup_logging)
logger = logging.getLogger(__name__)


class CiscoSecureAccessClient:
    """Client for interacting with Cisco Secure Access APIs with idempotent operations."""

    def __init__(self):
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

    @staticmethod
    def _build_destination_list() -> DestinationListCreate:
        """Build a destination list request object."""
        destination1 = DestinationListCreateDestinationsInner(
            comment="First warning url managed by SDK",
            type="ipv4",
            destination="127.0.0.1"
        )
        destination2 = DestinationListCreateDestinationsInner(
            comment="Second warning url managed by SDK",
            type="url",
            destination="http://foo.bar/blockwarn"
        )
        destination3 = DestinationListCreateDestinationsInner(
            comment="Next warning url managed by SDK",
            type="domain",
            destination="warn.foo.bar"
        )

        return DestinationListCreate(
            name="Test Destination List",
            destinations=[destination1, destination2, destination3],
            is_global=False,
            access=Access("block"),
            bundle_type_id=2
        )

    @staticmethod
    def _build_network_tunnel_group_1() -> AddNetworkTunnelGroupRequest:
        """Build the first network tunnel group request object."""
        return AddNetworkTunnelGroupRequest(
            region="us-test-1",
            name="Test Network Tunnel Group",
            device_type=DeviceType("other"),
            auth_id_prefix=AddNetworkTunnelGroupRequestAuthIdPrefix("test-prefix-1"),
            routing=RoutingRequest(
                type="static",
                data=RoutingRequestData(
                    StaticDataRequestObj(network_cidrs=["10.17.176.0/24"])
                )
            ),
            passphrase="Testpassphrase123"
        )

    @staticmethod
    def _build_network_tunnel_group_2() -> AddNetworkTunnelGroupRequest:
        """Build the second network tunnel group request object."""
        return AddNetworkTunnelGroupRequest(
            region="us-test-1",
            name="Test Network Tunnel Group 2",
            device_type=DeviceType("other"),
            auth_id_prefix=AddNetworkTunnelGroupRequestAuthIdPrefix("test-prefix-2"),
            routing=RoutingRequest(
                type="static",
                data=RoutingRequestData(
                    StaticDataRequestObj(network_cidrs=["10.17.178.0/24"])
                )
            ),
            passphrase="Testpassphrase123"
        )

    @staticmethod
    def _build_private_resource_1() -> PrivateResourceRequest:
        """Build the first private resource request object."""
        return PrivateResourceRequest(
            name="Test Private Resource 1",
            description="This is a test private resource 1",
            access_types=[AccessTypesRequestInner(NetworkBasedAccess(type="network"))],
            resource_addresses=[ResourceAddressesInner(
                destination_addr=["test.example.com", "192.168.1.1", "10.17.178.2/32"],
                protocol_ports=[
                    ResourceAddressesInnerProtocolPortsInner(protocol="TCP", ports="22,80,443")
                ]
            )]
        )

    @staticmethod
    def _build_private_resource_2() -> PrivateResourceRequest:
        """Build the second private resource request object."""
        return PrivateResourceRequest(
            name="Test Private Resource 2",
            description="This is a test private resource 2",
            access_types=[AccessTypesRequestInner(
                ClientBasedAccess(type="client", reachableAddresses=["10.10.10.3"])
            )],
            resource_addresses=[ResourceAddressesInner(
                destination_addr=["test.example.com", "192.168.1.1", "10.17.178.2/32"],
                protocol_ports=[
                    ResourceAddressesInnerProtocolPortsInner(protocol="TCP", ports="22,80,443")
                ]
            )]
        )

    @staticmethod
    def _build_access_policy_1(
        network_tunnel_group_id: str, private_resource_id: str
    ) -> AddRuleRequest:
        """Build the first access policy request object."""
        return AddRuleRequest(
            rule_name="Test Access Policy 1",
            rule_description="This is a test access policy 1",
            rule_action=RuleAction("allow"),
            rule_is_enabled=True,
            rule_settings=[
                RuleSettingsInner(
                    setting_name="umbrella.logLevel",
                    setting_value=SettingValue("LOG_ALL")
                ),
                RuleSettingsInner(
                    setting_name="umbrella.default.traffic",
                    setting_value=SettingValue("PRIVATE_NETWORK")
                )
            ],
            rule_conditions=[
                RuleConditionsInner(
                    attribute_name=AttributeName("umbrella.source.identity_ids"),
                    attribute_value=AttributeValue([int(network_tunnel_group_id)]),
                    attribute_operator="INTERSECT"
                ),
                RuleConditionsInner(
                    attribute_name=AttributeName("umbrella.destination.private_resource_ids"),
                    attribute_value=AttributeValue([int(private_resource_id)]),
                    attribute_operator="IN"
                )
            ]
        )

    @staticmethod
    def _build_access_policy_2(
        identity_id: str, destination_list_id: str
    ) -> AddRuleRequest:
        """Build the second access policy request object."""
        return AddRuleRequest(
            rule_name="Test Access Policy 2",
            rule_description="This is a test access policy 2",
            rule_action=RuleAction("block"),
            rule_is_enabled=True,
            rule_settings=[
                RuleSettingsInner(
                    setting_name="umbrella.logLevel",
                    setting_value=SettingValue("LOG_ALL")
                ),
                RuleSettingsInner(
                    setting_name="umbrella.default.traffic",
                    setting_value=SettingValue("PRIVATE_NETWORK")
                )
            ],
            rule_conditions=[
                RuleConditionsInner(
                    attribute_name=AttributeName("umbrella.source.identity_ids"),
                    attribute_value=AttributeValue([int(identity_id)]),
                    attribute_operator="="
                ),
                RuleConditionsInner(
                    attribute_name=AttributeName("umbrella.destination.destination_list_ids"),
                    attribute_value=AttributeValue([int(destination_list_id)]),
                    attribute_operator="="
                )
            ]
        )

    def create_destination_list(self) -> Any:
        """
        Create or retrieve an existing destination list.
        
        Returns:
            The destination list object (existing or newly created).
        """
        api_client = DestinationListsApi()
        self._set_authorization_header(api_client)

        destination_list_body = self._build_destination_list()
        list_name = destination_list_body.name

        try:
            logger.info(f"Checking for existing destination list: '{list_name}'")
            existing_lists = api_client.get_destination_lists_without_preload_content(limit=100)
            for existing_list in existing_lists.json().get("data", []):
                if existing_list["name"] == list_name:
                    logger.info(
                        f"Destination list '{list_name}' already exists with ID: {existing_list['id']}"
                    )
                    return existing_list

            logger.info(f"Creating new destination list '{list_name}'...")
            response = api_client.create_destination_list_without_preload_content(
                destination_list_body
            )
            logger.info(f"Successfully created destination list '{list_name}'")
            return response.json().get("data",[])
        except Exception as e:
            logger.error(f"Failed to create destination list '{list_name}': {e}")
            raise

    def create_network_tunnel_groups(self) -> Tuple[Any, Any]:
        """
        Create or retrieve existing network tunnel groups.
        
        Returns:
            Tuple of two network tunnel group objects (existing or newly created).
        """
        api_client = NetworkTunnelGroupsApi()
        self._set_authorization_header(api_client)

        ntg_body_1 = self._build_network_tunnel_group_1()
        ntg_body_2 = self._build_network_tunnel_group_2()

        try:
            logger.info("Fetching existing network tunnel groups")
            existing_groups = api_client.list_network_tunnel_groups_without_preload_content(limit=100)
            existing_names = {group["name"] for group in existing_groups.json().get("data", [])}

            responses = []
            for body in [ntg_body_1, ntg_body_2]:
                if body.name in existing_names:
                    logger.info(f"Network tunnel group '{body.name}' already exists")
                    for group in existing_groups.json().get("data", []):
                        if group["name"] == body.name:
                            responses.append(group)
                            break
                else:
                    logger.info(f"Creating new network tunnel group '{body.name}'...")
                    response = api_client.add_network_tunnel_group_without_preload_content(body)
                    responses.append(response.json())
                    logger.info(f"Successfully created network tunnel group '{body.name}'")

            return responses[0], responses[1]
        except Exception as e:
            logger.error(f"Failed to create network tunnel groups: {e}")
            raise

    def create_private_resources(self) -> Tuple[Any, Any]:
        """
        Create or retrieve existing private resources.
        
        Returns:
            Tuple of two private resource objects (existing or newly created).
        """
        api_client = PrivateResourcesApi()
        self._set_authorization_header(api_client)

        pr_body_1 = self._build_private_resource_1()
        pr_body_2 = self._build_private_resource_2()

        try:
            logger.info("Fetching existing private resources")
            existing_resources = api_client.list_private_resources_without_preload_content(limit=100)
            existing_names = {
                resource["name"] for resource in existing_resources.json().get("items", [])
            }
            logger.debug(f"Existing private resource names: {existing_names}")

            responses = []
            for body in [pr_body_1, pr_body_2]:
                if body.name in existing_names:
                    logger.info(f"Private resource '{body.name}' already exists")
                    for resource in existing_resources.json().get("items", []):
                        if resource["name"] == body.name:
                            responses.append(resource)
                            break
                else:
                    logger.info(f"Creating new private resource '{body.name}'...")
                    response = api_client.add_private_resource_without_preload_content(body)
                    responses.append(response.json())
                    logger.info(f"Successfully created private resource '{body.name}'")

            return responses[0], responses[1]
        except Exception as e:
            logger.error(f"Failed to create private resources: {e}")
            raise

    def list_network_tunnel_groups(self) -> List[Any]:
        """
        List all existing network tunnel groups.
        
        Returns:
            List of network tunnel group objects.
        """
        api_client = NetworkTunnelGroupsApi()
        self._set_authorization_header(api_client)

        try:
            logger.info("Fetching existing network tunnel groups")
            response = api_client.list_network_tunnel_groups_without_preload_content(limit=100)
            groups = response.json().get("data", [])
            logger.info(f"Found {len(groups)} network tunnel groups")
            return groups
        except Exception as e:
            logger.error(f"Failed to list network tunnel groups: {e}")
            raise

    def list_private_resources(self) -> List[Any]:
        """
        List all existing private resources.
        
        Returns:
            List of private resource objects.
        """
        api_client = PrivateResourcesApi()
        self._set_authorization_header(api_client)

        try:
            logger.info("Fetching existing private resources")
            response = api_client.list_private_resources_without_preload_content(limit=100)
            resources = response.json().get("items", [])
            logger.info(f"Found {len(resources)} private resources")
            return resources
        except Exception as e:
            logger.error(f"Failed to list private resources: {e}")
            raise

    def get_identities(self) -> Any:
        """
        Get the identities of the current user.
        
        Returns:
            The identities response.
        """
        api_client = IdentitiesApi()
        self._set_authorization_header(api_client)

        try:
            logger.info("Fetching identities for current user")
            response = api_client.get_identities(type="securityGroupTag", label="")
            logger.info("Successfully fetched identities")
            return response
        except Exception as e:
            logger.error(f"Failed to fetch identities: {e}")
            raise

    def create_access_policy_1(
        self, network_tunnel_group_id: str, private_resource_id: str
    ) -> Any:
        """
        Create or retrieve existing access policy 1.
        
        Args:
            network_tunnel_group_id: ID of the network tunnel group.
            private_resource_id: ID of the private resource.
            
        Returns:
            The access policy object (existing or newly created).
        """
        api_client = AccessRulesApi()
        self._set_authorization_header(api_client)

        access_policy_body = self._build_access_policy_1(
            network_tunnel_group_id, private_resource_id
        )
        rule_name = access_policy_body.rule_name

        try:
            logger.info(f"Checking for existing access policy: '{rule_name}'")
            existing_rules = api_client.list_rules_without_preload_content(
                limit=100, rule_name=rule_name
            )
            results = existing_rules.json().get("results", [])
            if results:
                rule_id = results[0].get("ruleId")
                logger.info(
                    f"Access policy '{rule_name}' already exists with ID: {rule_id}"
                )
                return results[0]

            logger.info(f"Creating new access policy '{rule_name}'...")
            response = api_client.add_rule(access_policy_body)
            logger.info(f"Successfully created access policy '{rule_name}'")
            return response
        except Exception as e:
            logger.error(f"Failed to create access policy '{rule_name}': {e}")
            raise

    def create_access_policy_2(
        self, identity_id: str, destination_list_id: str
    ) -> Any:
        """
        Create or retrieve existing access policy 2.
        
        Args:
            identity_id: ID of the identity.
            destination_list_id: ID of the destination list.
            
        Returns:
            The access policy object (existing or newly created).
        """
        api_client = AccessRulesApi()
        self._set_authorization_header(api_client)

        access_policy_body = self._build_access_policy_2(
            identity_id, destination_list_id
        )
        rule_name = access_policy_body.rule_name

        try:
            logger.info(f"Checking for existing access policy: '{rule_name}'")
            existing_rules = api_client.list_rules(limit=100, rule_name=rule_name)
            results = existing_rules.json().get("results", [])
            if results:
                rule_id = results[0].get("ruleId")
                logger.info(
                    f"Access policy '{rule_name}' already exists with ID: {rule_id}"
                )
                return results[0]

            logger.info(f"Creating new access policy '{rule_name}'...")
            response = api_client.add_rule(access_policy_body)
            logger.info(f"Successfully created access policy '{rule_name}'")
            return response
        except Exception as e:
            logger.error(f"Failed to create access policy '{rule_name}': {e}")
            raise


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging based on verbosity level.
    
    Args:
        verbose: If True, set logging level to DEBUG; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Cisco Secure Access API Client - Create and manage resources with idempotent operations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all operations (destination list, network tunnel groups, private resources, access policy)
  python complex_example.py --operation all

  # Create only a destination list
  python complex_example.py --operation destination-list

  # Create only network tunnel groups
  python complex_example.py --operation network-tunnel-groups

  # Create only private resources
  python complex_example.py --operation private-resources

  # Create access policy with specific IDs (use when resources already exist)
  python complex_example.py --operation access-policy --ntg-id 12345 --pr-id 67890

  # List existing network tunnel groups (without creating)
  python complex_example.py --operation list-network-tunnel-groups

  # List existing private resources (without creating)
  python complex_example.py --operation list-private-resources

  # Get identities for current user
  python complex_example.py --operation identities

  # Enable verbose/debug logging
  python complex_example.py --operation all --verbose

Environment Variables:
  CLIENT_ID       Cisco Secure Access API client ID
  CLIENT_SECRET   Cisco Secure Access API client secret
        """
    )

    parser.add_argument(
        '-o', '--operation',
        help="Operation to perform",
        required=True,
        choices=[
            'all',
            'destination-list',
            'network-tunnel-groups',
            'private-resources',
            'access-policy',
            'list-network-tunnel-groups',
            'list-private-resources',
            'identities'
        ],
        type=str
    )

    parser.add_argument(
        '--ntg-id',
        help="Network Tunnel Group ID (required for 'access-policy' operation when not running 'all')",
        required=False,
        type=str
    )

    parser.add_argument(
        '--pr-id',
        help="Private Resource ID (required for 'access-policy' operation when not running 'all')",
        required=False,
        type=str
    )

    parser.add_argument(
        '-v', '--verbose',
        help="Enable verbose/debug logging",
        action='store_true',
        default=False
    )

    return parser.parse_args()


def run_all_operations(client: CiscoSecureAccessClient) -> None:
    """
    Run all operations: create destination list, network tunnel groups,
    private resources, and access policy.
    
    Args:
        client: Initialized CiscoSecureAccessClient instance.
    """
    # Create destination list
    logger.info("Creating destination list...")
    destination_list = client.create_destination_list()
    destination_list_id = destination_list.get("id")
    logger.info(f"Destination List ID: {destination_list_id}")

    # Create network tunnel groups
    logger.info("Creating network tunnel groups...")
    response2 = client.create_network_tunnel_groups()
    network_tunnel_group_1_id = response2[0].get("id")
    logger.info(f"Network Tunnel Group 1 ID: {network_tunnel_group_1_id}")

    # Create private resources
    logger.info("Creating private resources...")
    response3 = client.create_private_resources()
    private_resource_1_id = response3[0].get("resourceId")
    logger.info(f"Private Resource 1 ID: {private_resource_1_id}")

    # Create access policy
    logger.info("Creating access policies...")
    response4 = client.create_access_policy_1(
        network_tunnel_group_1_id, private_resource_1_id
    )
    logger.info("Access policy 1 created successfully")

    # Get identities for current user (commented out - uncomment if needed)
    # logger.info("Fetching identities for current user...")
    # identities_response = client.get_identities()
    # identity_id = identities_response.data[0].id
    # logger.info(f"Identity ID: {identity_id}")

    # Create second access policy (commented out - uncomment if needed)
    # response5 = client.create_access_policy_2(identity_id, destination_list.id)
    # logger.info("Access policy 2 created successfully")

    logger.info("All resources created successfully")


def main():
    """Main execution function with CLI support."""
    args = parse_arguments()
    
    # Setup logging based on verbosity
    setup_logging(args.verbose)
    
    logger.info("Starting Cisco Secure Access client")

    try:
        client = CiscoSecureAccessClient()
        logger.info("Client initialized successfully")

        if args.operation == 'all':
            run_all_operations(client)

        elif args.operation == 'destination-list':
            logger.info("Creating destination list...")
            destination_list = client.create_destination_list()
            destination_list_id = destination_list.get("id")
            logger.info(f"Destination List ID: {destination_list_id}")
            print(f"Destination List created/found with ID: {destination_list_id}")

        elif args.operation == 'network-tunnel-groups':
            logger.info("Creating network tunnel groups...")
            response = client.create_network_tunnel_groups()
            ntg1_id = response[0].get("id")
            ntg2_id = response[1].get("id")
            logger.info(f"Network Tunnel Group 1 ID: {ntg1_id}")
            logger.info(f"Network Tunnel Group 2 ID: {ntg2_id}")
            print(f"Network Tunnel Groups created/found with IDs: {ntg1_id}, {ntg2_id}")

        elif args.operation == 'private-resources':
            logger.info("Creating private resources...")
            response = client.create_private_resources()
            pr1_id = response[0].get("resourceId")
            pr2_id = response[1].get("resourceId")
            logger.info(f"Private Resource 1 ID: {pr1_id}")
            logger.info(f"Private Resource 2 ID: {pr2_id}")
            print(f"Private Resources created/found with IDs: {pr1_id}, {pr2_id}")

        elif args.operation == 'access-policy':
            if not args.ntg_id or not args.pr_id:
                logger.error(
                    "Both --ntg-id and --pr-id are required for 'access-policy' operation"
                )
                print("Error: Both --ntg-id and --pr-id are required for 'access-policy' operation")
                sys.exit(1)
            
            logger.info("Creating access policy...")
            response = client.create_access_policy_1(args.ntg_id, args.pr_id)
            rule_id = response.get("ruleId") if hasattr(response, 'get') else getattr(response, 'rule_id', None)
            logger.info(f"Access Policy created/found with ID: {rule_id}")
            print(f"Access Policy created/found with ID: {rule_id}")

        elif args.operation == 'list-network-tunnel-groups':
            logger.info("Listing network tunnel groups...")
            groups = client.list_network_tunnel_groups()
            print(f"\nFound {len(groups)} Network Tunnel Groups:")
            for group in groups:
                print(f"  ID: {group.get('id')}, Name: {group.get('name')}")

        elif args.operation == 'list-private-resources':
            logger.info("Listing private resources...")
            resources = client.list_private_resources()
            print(f"\nFound {len(resources)} Private Resources:")
            for resource in resources:
                print(f"  ID: {resource.get('resourceId')}, Name: {resource.get('name')}")

        elif args.operation == 'identities':
            logger.info("Fetching identities for current user...")
            identities_response = client.get_identities()
            logger.info("Successfully fetched identities")
            print(f"Identities: {identities_response}")

        logger.info("Operation completed successfully")

    except Exception as e:
        logger.error(f"Failed to complete operations: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()