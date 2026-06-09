# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
import csv
import argparse
import logging
import requests
from access_token import generate_access_token
from config import config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "https://api.sse.cisco.com/policies/v2"
REPORTS_URL = "https://api.sse.cisco.com/reports/v2"

class ApplicationListManager:
    def __init__(self):
        self.access_token = generate_access_token()
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    def fetch_application_lists(self):
        """Fetch all application list summaries."""
        logger.info("Fetching application list summaries...")
        try:
            response = requests.get(f"{BASE_URL}/applicationLists", headers=self.headers, timeout=60)
            response.raise_for_status()
            return response.json().get("results", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching application lists: {e}")
            return []

    def fetch_application_name_maps(self):
        """Fetch {id: name} maps for applications and application categories.

        - Applications come from /reports/v2/applications (ApplicationsWithCategories).
        - Application *category* IDs used inside applicationLists belong to the
          policy taxonomy and must come from /policies/v2/applicationCategories,
          NOT from the `categories` field of /reports/v2/applications (that one
          is the reporting taxonomy and uses different IDs).
        """
        logger.info("Fetching application + category name maps...")
        app_map, cat_map = {}, {}
        try:
            r = requests.get(f"{REPORTS_URL}/applications", headers=self.headers, timeout=60)
            r.raise_for_status()
            data = r.json().get("data", {}) or {}
            app_map = {a["id"]: a.get("label") or a.get("name") for a in data.get("applications", [])}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching applications: {e}")
        try:
            # /policies/v2/applicationCategories returns a JSON object keyed
            # by category id, e.g. {"48": {"id": 48, "name": "Games", ...}, ...}.
            # (Not a list, not {"results": [...]}.) Pagination params are
            # accepted but the full set fits in one response in practice — we
            # still walk pages defensively in case that changes.
            page = 1
            while True:
                r = requests.get(
                    f"{BASE_URL}/applicationCategories",
                    headers=self.headers,
                    params={"page": page, "limit": 100},
                    timeout=60,
                )
                r.raise_for_status()
                payload = r.json()
                if isinstance(payload, dict) and "results" in payload:
                    cats = payload.get("results") or []
                elif isinstance(payload, dict):
                    cats = list(payload.values())
                elif isinstance(payload, list):
                    cats = payload
                else:
                    cats = []
                if not cats:
                    break
                for c in cats:
                    if isinstance(c, dict) and "id" in c:
                        cat_map[c["id"]] = c.get("name") or c.get("label")
                if len(cats) < 100:
                    break
                page += 1
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching application categories: {e}")
        logger.info(f"Loaded {len(app_map)} applications, {len(cat_map)} categories.")
        return app_map, cat_map

    def humanize(self, enriched_data, app_map, cat_map):
        """Replace applicationIds/applicationCategoryIds with name lists.

        Logs an INFO line for every ID that cannot be resolved, including the
        owning application-list name so the operator can chase it down.
        """
        out = []
        unresolved_apps = unresolved_cats = 0
        for entry in enriched_data:
            list_name = entry.get("applicationListName", f"<id {entry.get('applicationListId')}>")
            new_entry = {k: v for k, v in entry.items()
                         if k not in ("applicationIds", "applicationCategoryIds")}

            app_names = []
            for aid in entry.get("applicationIds", []):
                name = app_map.get(aid)
                if name is None:
                    unresolved_apps += 1
                    logger.info(
                        "Unresolved application ID %s in list '%s' — not found in /reports/v2/applications",
                        aid, list_name,
                    )
                    app_names.append(f"Unknown ID: {aid}")
                else:
                    app_names.append(name)
            new_entry["applicationNames"] = app_names

            cat_names = []
            for cid in entry.get("applicationCategoryIds", []):
                name = cat_map.get(cid)
                if name is None:
                    unresolved_cats += 1
                    logger.info(
                        "Unresolved application-category ID %s in list '%s' — not found in /policies/v2/applicationCategories",
                        cid, list_name,
                    )
                    cat_names.append(f"Unknown ID: {cid}")
                else:
                    cat_names.append(name)
            new_entry["applicationCategoryNames"] = cat_names

            out.append(new_entry)

        if unresolved_apps or unresolved_cats:
            logger.info(
                "Unresolved totals: %d application ID(s), %d category ID(s)",
                unresolved_apps, unresolved_cats,
            )
        return out

    def fetch_list_details(self, list_id):
        """Fetch detailed items (applicationIds/categories) for a specific list."""
        try:
            response = requests.get(f"{BASE_URL}/applicationLists/{list_id}", headers=self.headers, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching details for list {list_id}: {e}")
            return {}

    def save_as_json(self, data, filename):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Successfully saved to JSON: {filename}")

    def save_as_csv(self, data, filename):
        """Saves enriched data to CSV. Note: list fields are joined as strings."""
        if not data:
            return

        # Flatten the data for CSV — handle both ID and human-readable schemas
        flat_data = []
        for item in data:
            flat_item = item.copy()
            for key in ('applicationIds', 'applicationCategoryIds',
                        'applicationNames', 'applicationCategoryNames'):
                if key in flat_item:
                    flat_item[key] = ",".join(map(str, flat_item.get(key) or []))
            flat_data.append(flat_item)

        keys = flat_data[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(flat_data)
        logger.info(f"Successfully saved to CSV: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Utility to list and export Cisco Secure Access Application Lists with details")
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help="Output format")
    parser.add_argument('--file', default='app_lists_full_backup', help="Output filename (without extension)")
    parser.add_argument('--human-readable', action='store_true',
                        help="Replace applicationIds / applicationCategoryIds with their resolved names")
    
    args = parser.parse_args()
    
    manager = ApplicationListManager()
    
    # 1. Get all summaries
    summaries = manager.fetch_application_lists()
    if not summaries:
        logger.warning("No application lists found.")
        return

    # 2. Enrich with details
    enriched_data = []
    logger.info(f"Enriching {len(summaries)} lists with details...")
    for summary in summaries:
        list_id = summary.get("applicationListId")
        details = manager.fetch_list_details(list_id)
        # Merge summary and detail
        enriched_data.append({**summary, **details})

    # 3. Optionally resolve IDs → names
    if args.human_readable:
        app_map, cat_map = manager.fetch_application_name_maps()
        if not app_map and not cat_map:
            logger.error("Could not fetch name maps; aborting human-readable conversion.")
            return
        enriched_data = manager.humanize(enriched_data, app_map, cat_map)

    # 4. Export
    filename = f"{args.file}.{args.format}"
    if args.format == 'json':
        manager.save_as_json(enriched_data, filename)
    else:
        manager.save_as_csv(enriched_data, filename)

if __name__ == "__main__":
    main()