# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
CLI utility to list and backup Zero Trust Access (ZTA) enrolled clients
and their associated user details from Cisco Secure Access.

Usage:
    # List all ZTA clients with user summaries
    python list_zta_clients.py --operation list

    # List with pagination control
    python list_zta_clients.py --operation list --page-size 200

    # List and filter by active devices only
    python list_zta_clients.py --operation list --active-only

    # Backup all ZTA client data to JSON
    python list_zta_clients.py --operation backup

    # Backup to a custom file
    python list_zta_clients.py --operation backup --file my_zta_backup.json

    # Backup only clients with active device certificates
    python list_zta_clients.py --operation backup --active-only

    # Show summary statistics
    python list_zta_clients.py --operation summary

Requirements:
    - Set CLIENT_ID and CLIENT_SECRET environment variables before use.
    - Ensure all dependencies in requirements.txt are installed.
"""

from secure_access.api_client import ApiClient
from access_token import generate_access_token
from secure_access.configuration import Configuration
from config import config
import json
import argparse
import logging
import sys
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
logger.addHandler(handler)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Cisco Secure Access API base URL
BASE_URL = "https://api.sse.cisco.com"

# API endpoints
IDENTITIES_ENDPOINT = f"{BASE_URL}/reports/v2/identities"
USER_SUMMARIES_ENDPOINT = f"{BASE_URL}/admin/v2/ztna/userSummaries"
ZTNA_ACTIVITY_ENDPOINT = f"{BASE_URL}/reports/v2/activity/ztna"


class ZTAClientLister:
    """
    Handles listing and backing up Zero Trust Access (ZTA) enrolled clients
    and their associated user/device information.
    """

    def __init__(self, page_size=500, active_only=False, retries=None):
        """
        Initialize the ZTAClientLister.

        :param page_size: Number of identity records to fetch per page (max varies by endpoint)
        :param active_only: If True, only include clients with active device certificates
        :param retries: Retry configuration for API requests
        """
        self.access_token = generate_access_token()
        self.configuration = Configuration(
            access_token=self.access_token,
            retries=retries
        )
        self.api_client = ApiClient(configuration=self.configuration)
        self.page_size = page_size
        self.active_only = active_only
        self.backup_file_name = "zta_clients_backup.json"

        # Internal data stores
        self.identities: List[Dict[str, Any]] = []
        self.zta_clients: List[Dict[str, Any]] = []

        # Build authorization headers for direct REST calls
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    # ------------------------------------------------------------------
    # Identity fetching
    # ------------------------------------------------------------------

    def _fetch_identities_page(self, offset: int, limit: int) -> List[Dict[str, Any]]:
        """
        Fetch a single page of directory-user identities.

        :param offset: Starting offset
        :param limit: Number of records to fetch
        :return: List of identity dicts
        """
        params = {
            "limit": limit,
            "offset": offset,
            "identitytypes": "directory_user"
        }

        try:
            response = requests.get(
                IDENTITIES_ENDPOINT,
                headers=self.headers,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json().get("data", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching identities at offset {offset}: {e}")
            return []

    def fetch_all_identities(self) -> List[Dict[str, Any]]:
        """
        Fetch all directory-user identities with automatic pagination.

        :return: Complete list of identity dicts
        """
        logger.info("Fetching all directory-user identities...")
        self.identities = []
        offset = 0

        while True:
            logger.info(f"Fetching identities at offset {offset}, limit {self.page_size}...")
            page_data = self._fetch_identities_page(offset, self.page_size)

            if not page_data:
                logger.info(f"No more identities at offset {offset}. Stopping.")
                break

            self.identities.extend(page_data)
            logger.info(f"Retrieved {len(page_data)} identities (total so far: {len(self.identities)})")

            if len(page_data) < self.page_size:
                break

            offset += self.page_size

        logger.info(f"Total identities fetched: {len(self.identities)}")
        return self.identities

    # ------------------------------------------------------------------
    # User summaries (device certificate counts)
    # ------------------------------------------------------------------

    def _fetch_user_summaries(self, user_ids: List[int]) -> List[Dict[str, Any]]:
        """
        Fetch ZTA user summaries for a batch of user IDs.

        :param user_ids: List of numeric user IDs
        :return: List of user summary dicts
        """
        if not user_ids:
            return []

        ids_param = ",".join(str(uid) for uid in user_ids)
        url = f"{USER_SUMMARIES_ENDPOINT}?userIds={ids_param}"

        try:
            response = requests.get(url, headers=self.headers, timeout=60)
            response.raise_for_status()
            return response.json().get("users", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching user summaries: {e}")
            return []

    # ------------------------------------------------------------------
    # ZTNA recent activity (optional enrichment)
    # ------------------------------------------------------------------

    def _fetch_ztna_activity(self, from_ts: int, to_ts: int,
                             limit: int = 5000, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Fetch a page of ZTNA activity records.

        :param from_ts: Start timestamp in epoch milliseconds
        :param to_ts: End timestamp in epoch milliseconds
        :param limit: Page size
        :param offset: Offset
        :return: List of activity dicts
        """
        params = {
            "from": from_ts,
            "to": to_ts,
            "limit": limit,
            "offset": offset
        }

        try:
            response = requests.get(
                ZTNA_ACTIVITY_ENDPOINT,
                headers=self.headers,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json().get("data", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching ZTNA activity: {e}")
            return []

    def fetch_recent_ztna_activity(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Fetch ZTNA activity for the last N hours with automatic pagination.

        :param hours: How many hours of history to retrieve
        :return: List of ZTNA activity records
        """
        now = datetime.utcnow()
        to_ts = int(now.timestamp() * 1000)
        from_ts = to_ts - (hours * 3600 * 1000)

        logger.info(f"Fetching ZTNA activity for the last {hours} hour(s)...")

        all_activity: List[Dict[str, Any]] = []
        offset = 0
        page_limit = 5000
        max_offset = 15000

        while offset < max_offset:
            page_data = self._fetch_ztna_activity(from_ts, to_ts, page_limit, offset)

            if not page_data:
                break

            all_activity.extend(page_data)
            logger.info(f"ZTNA activity page at offset {offset}: {len(page_data)} records "
                        f"(total: {len(all_activity)})")

            if len(page_data) < page_limit:
                break

            offset += page_limit

        logger.info(f"Total ZTNA activity records fetched: {len(all_activity)}")
        return all_activity

    # ------------------------------------------------------------------
    # Build combined ZTA client records
    # ------------------------------------------------------------------

    def build_zta_client_list(self, include_activity: bool = False,
                              activity_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Build a comprehensive list of ZTA clients by combining identity data
        with device certificate summaries and optional recent activity.

        :param include_activity: Whether to enrich with recent ZTNA activity
        :param activity_hours: Hours of ZTNA activity history to include
        :return: List of enriched ZTA client records
        """
        if not self.identities:
            self.fetch_all_identities()

        if not self.identities:
            logger.warning("No identities found. Nothing to process.")
            return []

        # ----- Fetch user summaries in batches -----
        batch_size = 100
        summaries_by_user_id: Dict[int, Dict[str, Any]] = {}

        logger.info("Fetching ZTA user summaries in batches...")
        for i in range(0, len(self.identities), batch_size):
            batch = self.identities[i:i + batch_size]
            user_ids = [identity["id"] for identity in batch]
            summaries = self._fetch_user_summaries(user_ids)

            for summary in summaries:
                uid = int(summary.get("userId", 0))
                summaries_by_user_id[uid] = summary

            logger.debug(f"Processed summary batch {i // batch_size + 1} "
                         f"({len(summaries)} summaries returned)")

        # ----- Optionally fetch recent ZTNA activity -----
        activity_by_identity: Dict[str, List[Dict[str, Any]]] = {}
        if include_activity:
            activity_records = self.fetch_recent_ztna_activity(hours=activity_hours)
            for record in activity_records:
                # Group activity by the identity label or ID
                identity_label = ""
                for ident in record.get("identities", []):
                    if ident.get("type", {}).get("type") == "directory_user":
                        identity_label = ident.get("label", "")
                        break
                if not identity_label:
                    identity_label = str(record.get("originId", "unknown"))

                activity_by_identity.setdefault(identity_label, []).append({
                    "timestamp": record.get("timestamp"),
                    "verdict": record.get("verdict"),
                    "action": record.get("action"),
                    "privateResources": [
                        app.get("label", "unknown")
                        for app in record.get("allapplications", [])
                        if isinstance(app, dict) and app.get("type") == "PRIVATE"
                    ],
                    "destinationIp": record.get("destinationIp"),
                    "destinationPort": record.get("destinationPort"),
                    "sourceIp": record.get("sourceIp"),
                })

        # ----- Build combined records -----
        logger.info("Building combined ZTA client records...")
        self.zta_clients = []

        for identity in self.identities:
            uid = identity.get("id")
            label = identity.get("label", "")

            # Parse display name and email from label (format: "Name (email)")
            display_name = label
            email = ""
            if " (" in label and label.endswith(")"):
                parts = label.rsplit(" (", 1)
                display_name = parts[0]
                email = parts[1].rstrip(")")

            summary = summaries_by_user_id.get(uid, {})
            device_counts = summary.get("deviceCertificateCounts", {})

            active_count = device_counts.get("active", 0)
            expired_count = device_counts.get("expired", 0)
            revoked_count = device_counts.get("revoked", 0)
            total_devices = active_count + expired_count + revoked_count
            is_enrolled = uid in summaries_by_user_id

            # Apply active-only filter
            if self.active_only and active_count == 0:
                continue

            client_record: Dict[str, Any] = {
                "userId": uid,
                "displayName": display_name,
                "email": email,
                "identityType": identity.get("type", {}).get("type", ""),
                "identityLabel": label,
                "enrolled": is_enrolled,
                "devices": {
                    "active": active_count,
                    "expired": expired_count,
                    "revoked": revoked_count,
                    "total": total_devices
                },
            }

            # Include any extra fields the user summary exposes
            for key in ("status", "lastAuthenticated", "registeredAt",
                        "clientVersion", "os", "osVersion", "deviceName",
                        "tunnelType", "macAddress", "serialNumber"):
                if key in summary:
                    client_record[key] = summary[key]

            # Attach recent activity if requested
            if include_activity:
                user_activity = activity_by_identity.get(label, [])
                client_record["recentActivityCount"] = len(user_activity)
                # Keep only last 10 entries for readability
                client_record["recentActivity"] = sorted(
                    user_activity, key=lambda x: x.get("timestamp", 0), reverse=True
                )[:10]

            self.zta_clients.append(client_record)

        logger.info(f"Built {len(self.zta_clients)} ZTA client records "
                    f"(active_only={self.active_only})")
        return self.zta_clients

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def save_backup(self, filename: Optional[str] = None):
        """
        Save ZTA client data to a JSON file.

        :param filename: Optional custom filename
        """
        if filename:
            self.backup_file_name = filename

        try:
            with open(self.backup_file_name, "w") as f:
                json.dump(self.zta_clients, f, indent=4, default=str)
            logger.info(f"Backup saved to {self.backup_file_name} "
                        f"with {len(self.zta_clients)} records")
        except Exception as e:
            logger.error(f"Error saving backup: {e}")

    def print_summary(self):
        """
        Print a summary of ZTA client enrollment statistics.
        """
        if not self.zta_clients:
            logger.warning("No ZTA client data available for summary")
            return

        total = len(self.zta_clients)
        enrolled = sum(1 for c in self.zta_clients if c.get("enrolled"))
        not_enrolled = total - enrolled
        with_active = sum(1 for c in self.zta_clients if c["devices"]["active"] > 0)
        total_active_devices = sum(c["devices"]["active"] for c in self.zta_clients)
        total_expired_devices = sum(c["devices"]["expired"] for c in self.zta_clients)
        total_revoked_devices = sum(c["devices"]["revoked"] for c in self.zta_clients)
        multi_device = sum(1 for c in self.zta_clients if c["devices"]["active"] > 1)

        pct_active = (with_active / total * 100) if total > 0 else 0

        print("\n" + "=" * 60)
        print("  ZERO TRUST ACCESS — CLIENT ENROLLMENT SUMMARY")
        print("=" * 60)
        print(f"  Total identities processed : {total}")
        print(f"  Enrolled (have summary)    : {enrolled}")
        print(f"  Not enrolled               : {not_enrolled}")
        print(f"  With active device(s)      : {with_active} ({pct_active:.1f}%)")
        print(f"  With multiple active devs  : {multi_device}")
        print("-" * 60)
        print(f"  Total active certificates  : {total_active_devices}")
        print(f"  Total expired certificates : {total_expired_devices}")
        print(f"  Total revoked certificates : {total_revoked_devices}")
        print("=" * 60 + "\n")

    def print_clients(self, max_rows: Optional[int] = None):
        """
        Print ZTA clients as formatted JSON to stdout.

        :param max_rows: Optional limit on number of records to print
        """
        data = self.zta_clients[:max_rows] if max_rows else self.zta_clients
        print(json.dumps(data, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(
        description="List and backup Zero Trust Access (ZTA) enrolled clients from Cisco Secure Access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all ZTA clients (prints JSON to stdout)
  python list_zta_clients.py --operation list

  # List only clients with active devices
  python list_zta_clients.py --operation list --active-only

  # List with recent ZTNA activity enrichment (last 24h)
  python list_zta_clients.py --operation list --include-activity

  # List with 48 hours of activity history
  python list_zta_clients.py --operation list --include-activity --activity-hours 48

  # Print only first 10 clients
  python list_zta_clients.py --operation list --max-rows 10

  # Show enrollment summary statistics
  python list_zta_clients.py --operation summary

  # Backup all ZTA client data to JSON
  python list_zta_clients.py --operation backup

  # Backup active-only clients to custom file
  python list_zta_clients.py --operation backup --active-only --file active_clients.json

  # Backup with activity enrichment
  python list_zta_clients.py --operation backup --include-activity --activity-hours 12
        """
    )

    parser.add_argument(
        '--operation',
        help="Operation to perform",
        required=True,
        choices=["list", "backup", "summary"],
        type=str
    )

    parser.add_argument(
        '--page-size',
        help="Number of identity records per API page (default: 500)",
        required=False,
        type=int,
        default=500
    )

    parser.add_argument(
        '--active-only',
        help="Only include clients with at least one active device certificate",
        action='store_true'
    )

    parser.add_argument(
        '--include-activity',
        help="Enrich client records with recent ZTNA activity data",
        action='store_true'
    )

    parser.add_argument(
        '--activity-hours',
        help="Hours of ZTNA activity history to include (default: 24)",
        required=False,
        type=int,
        default=24
    )

    parser.add_argument(
        '--max-rows',
        help="Maximum number of client records to display (list operation only)",
        required=False,
        type=int
    )

    parser.add_argument(
        '--file',
        help="Custom backup file name (default: zta_clients_backup.json)",
        required=False,
        type=str
    )

    args = parser.parse_args()

    logger.info("Starting ZTA Client Lister...")

    lister = ZTAClientLister(
        page_size=args.page_size,
        active_only=args.active_only,
        retries=config.get_retry()
    )

    # Build the client list (shared across all operations)
    lister.build_zta_client_list(
        include_activity=args.include_activity,
        activity_hours=args.activity_hours
    )

    if not lister.zta_clients:
        logger.warning("No ZTA clients found matching the specified criteria")
        sys.exit(0)

    # Execute requested operation
    if args.operation == "list":
        lister.print_clients(max_rows=args.max_rows)
        logger.info(f"Listed {len(lister.zta_clients)} ZTA client(s)")

    elif args.operation == "backup":
        lister.save_backup(filename=args.file)
        logger.info("Backup operation completed successfully")

    elif args.operation == "summary":
        lister.print_summary()

    logger.info("Operation completed successfully")


if __name__ == "__main__":
    main()