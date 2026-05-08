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
        """Saves enriched data to CSV. Note: applicationIds are joined as strings."""
        if not data:
            return
        
        # Flatten the data for CSV
        flat_data = []
        for item in data:
            flat_item = item.copy()
            flat_item['applicationIds'] = ",".join(map(str, item.get('applicationIds', [])))
            flat_item['applicationCategoryIds'] = ",".join(map(str, item.get('applicationCategoryIds', [])))
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

    # 3. Export
    filename = f"{args.file}.{args.format}"
    if args.format == 'json':
        manager.save_as_json(enriched_data, filename)
    else:
        manager.save_as_csv(enriched_data, filename)

if __name__ == "__main__":
    main()