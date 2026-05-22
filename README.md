[![PyPI version](https://img.shields.io/pypi/v/secureaccess.svg)](https://pypi.org/project/secureaccess/)
[![Python versions](https://img.shields.io/pypi/pyversions/secureaccess.svg)](https://pypi.org/project/secureaccess/)

# Cisco Secure Access Python SDK

A Python SDK for interacting with Cisco Secure Access APIs.

## Requirements

- Python 3.9 or higher
- Valid API credentials

## Installation

### From PyPI (recommended)

```sh
pip install secureaccess
```

> The distribution name on PyPI is `secureaccess`, but the import name is `secure_access`
> (e.g. `from secure_access.configuration import Configuration`).

### From source

```sh
git clone https://github.com/CiscoDevNet/cisco-secure-access-python-sdk.git
cd cisco-secure-access-python-sdk
pip install .
```

### Prerequisites

First, install the required dependencies:

```sh
pip install -r requirements.txt
```

### Setuptools

Install via [Setuptools](http://pypi.python.org/pypi/setuptools).

```sh
python setup.py install --user
```

## Configuration

Set up your API credentials by using environment variables:

### Environment Variables

```bash
export CLIENT_ID="your_client_id"
export CLIENT_SECRET="your_client_secret"
```

### Retry Configuration

The SDK supports automatic retry with exponential backoff using [urllib3's Retry](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry) class. Configure retries using the `retries` parameter in `Configuration`:

```python
from urllib3.util.retry import Retry
from secure_access.configuration import Configuration
from secure_access.api_client import ApiClient

configuration = Configuration(
    access_token=access_token,
    retries=Retry(
        total=3,  # Maximum number of retry attempts
        backoff_factor=3,  # Wait time multiplier between retries: {backoff_factor} * (2 ** (retry_number - 1)) seconds. With factor=3: 0s, 3s, 6s delays
        status_forcelist=[429],  # HTTP status codes that trigger a retry (429 = Too Many Requests / rate limited)
        allowed_methods=["GET", "POST"]  # HTTP methods that are allowed to be retried
    )
)
api_client = ApiClient(configuration=configuration)
```

To disable retry, omit the `retries` parameter or set it to `None`.

### API Base URL Configuration

The Cisco Secure Access API uses different base URLs depending on the endpoint type. The SDK provides three server configurations:

| Server Index | URL | Use Case |
|---|---|---|
| `0` | `https://api.sse.cisco.com` | Admin, Policy, and Management APIs |
| `1` | `https://api.sse.cisco.com/reports.{region}/v2` | Reporting APIs (with region variable) |
| `2` | `https://api.sse.cisco.com/{basePath}` | Reporting APIs (without region, defaults to `reports/v2`) |

#### Reporting APIs (with region)

Reporting endpoints (e.g., Top Identities, Top Destinations, Activity) require a region-specific base URL. You can configure this using either `server_index` with `server_variables`, or by setting the `host` directly.

**Option 1: Using `server_index` and `server_variables`**

```python
configuration = Configuration(
    access_token=access_token,
    server_index=1,
    server_variables={"region": "us"},  # "us" or "eu"
)
```

**Option 2: Using `host` directly**

```python
configuration = Configuration(
    access_token=access_token,
    host="https://api.sse.cisco.com/reports.us/v2",
)
```

#### Reporting APIs (without region)

If you do not need region-specific routing, use `server_index=2` which defaults to `reports/v2`.

**Option 1: Using `server_index`**

```python
configuration = Configuration(
    access_token=access_token,
    server_index=2,
)
```

**Option 2: Using `host` directly**

```python
configuration = Configuration(
    access_token=access_token,
    host="https://api.sse.cisco.com/reports/v2",
)
```

#### Admin / Policy / Management APIs

Non-reporting endpoints (e.g., Access Rules, Destination Lists, Roaming Computers) use the default base URL (`https://api.sse.cisco.com`, server index `0`). No additional configuration is needed — this is the default when `server_index` and `host` are not specified.

```python
configuration = Configuration(
    access_token=access_token,
)
```

> **Note:** If you need to use both reporting and non-reporting APIs in the same script, create separate `Configuration` and `ApiClient` instances for each.

## Examples

The `examples/` folder contains sample scripts demonstrating various use cases with the Cisco Secure Access SDK:

### Access Rule Backup and Restore
Backup and restore access rules
```sh
python examples/access_rule_backup_restore.py -h
usage: access_rule_backup_restore.py [-h] -t {backup,restore} [-o OFFSET] [-l LIMIT] [-r RULES [RULES ...]]

Utility to backup and restore access rules

options:
  -h, --help            show this help message and exit
  -t {backup,restore}, --type {backup,restore}
                        Type of the operation to be performed i.e. either backup or restore the access rules.
  -o OFFSET, --offset OFFSET
                        Starting offset to fetch the access rules
  -l LIMIT, --limit LIMIT
                        limit to fetch the access rules in a call
  -r RULES [RULES ...], --rules RULES [RULES ...]
                        list of rule id's to filter the Access Rules
```

### Roaming Computers Backup
Backup roaming computer configurations
```sh
python examples/roaming_computers_backup.py -h
usage: roaming_computers_backup.py [-h] --operation {backup,filter,complex-filter,analyze} [--page-size PAGE_SIZE] [--name NAME]
                                   [--status STATUS] [--swg-status SWG_STATUS] [--last-sync-before LAST_SYNC_BEFORE]
                                   [--last-sync-after LAST_SYNC_AFTER] [--filter-key FILTER_KEY] [--filter-value FILTER_VALUE]
                                   [--filter-expression FILTER_EXPRESSION] [--backup-file BACKUP_FILE] [--apply-simple-filter]
                                   [--apply-complex-filter]

Utility to backup roaming computers and apply filters

options:
  -h, --help            show this help message and exit
  --operation {backup,filter,complex-filter,analyze}
                        Operation to perform
  --page-size PAGE_SIZE
                        Number of records per page (max: 100)
  --name NAME           Filter by roaming computer name
  --status STATUS       Filter by DNS-layer security status
  --swg-status SWG_STATUS
                        Filter by Internet security (SWG) status
  --last-sync-before LAST_SYNC_BEFORE
                        Filter by last sync before this date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
  --last-sync-after LAST_SYNC_AFTER
                        Filter by last sync after this date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
  --filter-key FILTER_KEY
                        Key to filter on (supports dot notation for nested keys)
  --filter-value FILTER_VALUE
                        Value to match for filtering
  --filter-expression FILTER_EXPRESSION
                        Complex filter expression with logical operators and time functions
  --backup-file BACKUP_FILE
                        Custom backup file name
  --apply-simple-filter
                        Apply simple filter immediately after backup
  --apply-complex-filter
                        Apply complex filter immediately after backup
```

### Destination Lists Manager
Manage destination lists
```sh
python examples/destination_lists_manager.py -h
usage: destination_list_manager.py [-h] {destination-lists,destinations} ...

Cisco Secure Access Destination Management Tool

positional arguments:
  {destination-lists,destinations}
                        Available commands
    destination-lists   Manage destination lists
    destinations        Manage destinations

options:
  -h, --help            show this help message and exit
```

### Alert Rules Management
Manage alert rules (list, get, create, update, delete, update-status)
```sh
python examples/alert_rules.py -h
usage: alert_rules.py [-h] {list,get,create,update,delete,update-status} ...

Cisco Secure Access Alert Rules Management CLI

positional arguments:
  {list,get,create,update,delete,update-status}
                        Available commands
    list                List all alert rules
    get                 Get a specific alert rule by ID
    create              Create a new alert rule
    update              Update an existing alert rule
    delete              Delete one or more alert rules
    update-status       Update the status of alert rules

options:
  -h, --help            show this help message and exit
```

### Alert Integration
Create webhook integrations and associated alert rules end-to-end
```sh
python examples/alert_integration.py
```

### Complex Example
Class-based client with idempotent operations for destination lists, network tunnel groups, private resources, and access policies
```sh
python examples/complex_example.py -h
usage: complex_example.py [-h] -o {all,destination-list,network-tunnel-groups,private-resources,access-policy,list-network-tunnel-groups,list-private-resources,identities}
                          [--ntg-id NTG_ID] [--pr-id PR_ID] [-v]

Cisco Secure Access API Client - Create and manage resources with idempotent operations.

options:
  -h, --help            show this help message and exit
  -o, --operation {all,destination-list,network-tunnel-groups,private-resources,access-policy,list-network-tunnel-groups,list-private-resources,identities}
                        Operation to perform
  --ntg-id NTG_ID       Network Tunnel Group ID (required for 'access-policy' operation when not running 'all')
  --pr-id PR_ID         Private Resource ID (required for 'access-policy' operation when not running 'all')
  -v, --verbose         Enable verbose/debug logging
```

### DLP Rule Events
Retrieve DLP rule events (Real-Time, SaaS API, AI Guardrails) with regional endpoint support
```sh
python examples/dlp_rule_events.py -h
usage: dlp_rule_events.py [-h] [--region {us,eu}] {list-realtime,list-saas,list-ai-guardrails,get} ...

Cisco Secure Access DLP Rule Events Management CLI

positional arguments:
  {list-realtime,list-saas,list-ai-guardrails,get}
                        Available commands
    list-realtime       List Real-Time DLP rule events
    list-saas           List SaaS API DLP rule events
    list-ai-guardrails  List AI Guardrails DLP rule events
    get                 Get DLP event details by ID

options:
  -h, --help            show this help message and exit
  --region {us,eu}      API region: 'us' (default) or 'eu'
```

### Top Identities List
Fetch top identities with pagination, export to JSON/CSV, and optional chart visualization
```sh
python examples/top_identities_list.py -h
usage: top_identities_list.py [-h] [--from FROM] [--to TO] [--identitytypes TYPES]
                              [--top-n N] [--format {json,csv}] [--output FILE]
                              [--chart {none,bar,horizontal_bar,line,pie}]
                              [--chart-output FILE] [--page-delay SECONDS]

Fetch all top identities from Cisco Secure Access (last 7 days by default).

options:
  -h, --help            show this help message and exit
  --from FROM           Start of time range (default: -7days)
  --to TO               End of time range (default: now)
  --identitytypes TYPES Identity type or comma-delimited list (e.g. 'roaming computers,users')
  --top-n N             Keep only the top N records after fetching (default: all)
  --format {json,csv}   Output format: json or csv (default: json)
  --output FILE         Output file path (- for stdout, default: top_identities.json)
  --chart {none,bar,horizontal_bar,line,pie}
                        Chart type for visualization (default: none)
  --chart-output FILE   File path to save the chart PNG (default: top_identities_chart.png)
  --page-delay SECONDS  Seconds to sleep between page batches (default: 0)
```

### Key Admin API Management
Manage API keys and administrative functions
```sh
python examples/key_admin_api.py
```
# Cisco Cloud Security Development Samples

## Introduction and Terms of Service
The following include examples and samples that can help you when interacting or building integrations with Cisco Secure Access. These samples, scripts, collections and guides are supplied to customers as examples which customers are free to use or modify for use with your existing subscriptions under the terms of the [attached license](https://github.com/CiscoDevNet/cloud-security-early-adoption/blob/master/LICENSE) and the [Cisco DevNet Terms Of Service](https://developer.cisco.com/site/license/terms-and-conditions/).
