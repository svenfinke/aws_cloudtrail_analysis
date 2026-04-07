# aws_cloudtrail_analysis

A command-line tool for analysing AWS CloudTrail logs to detect and report
on user / role activity.  Designed to help security teams quickly answer
questions like:

> *"Did `github_role` make any EC2 calls in the last 30 days, and did any
> of them fail?"*

---

## Features

| Feature | Details |
|---|---|
| **User / role filters** | Filter by exact IAM username **or** substring-match on assumed-role session names |
| **Service filter** | Narrow results to a specific AWS service (e.g. `ec2`, `s3`, `iam`) |
| **Resource filter** | Partial-match on resource names in CloudTrail events |
| **Event-name filter** | Limit to specific API calls (e.g. `RunInstances`, `PutObject`) |
| **Write-only mode** | Skip read-only calls (`Describe*`, `List*`, `Get*`, …) |
| **Errors-only mode** | Show only events that resulted in an API error |
| **Flexible time range** | `--days N` (default 30) or explicit `--start-time` / `--end-time` |
| **SSO support** | Works with any AWS named profile, including SSO profiles |
| **Output formats** | Rich colour table (default), clean JSON, or CSV |
| **File export** | Pipe JSON / CSV to a file with `--output-file` |

---

## Requirements

- Python 3.9 or newer
- An AWS account with CloudTrail enabled in the target region

---

## Installation

```bash
# 1. Clone / download the repository
git clone https://github.com/svenfinke/aws_cloudtrail_analysis.git
cd aws_cloudtrail_analysis

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install runtime dependencies
pip install -r requirements.txt
```

---

## AWS authentication

The tool uses the standard boto3 credential chain, so any method that works
with the AWS CLI will work here.

### Long-term credentials

```bash
# Configure a named profile with access key / secret
aws configure --profile my-profile
```

### SSO (recommended for organisations)

```bash
# One-time SSO configuration
aws configure sso --profile my-sso-profile

# Login before running the tool (tokens expire – repeat as needed)
aws sso login --profile my-sso-profile
```

Then pass `--profile my-sso-profile` to every invocation.

If you omit `--profile`, boto3 uses the default credential chain
(environment variables → `~/.aws/credentials` → instance/container metadata).

---

## Usage

```
python cloudtrail_analysis.py [OPTIONS]
```

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--profile PROFILE` | `-p` | – | AWS named / SSO profile |
| `--region REGION` | `-r` | profile/env default | AWS region to query |
| `--username USERNAME` | `-u` | – | Exact IAM username (pushed to CloudTrail API – most efficient) |
| `--role ROLE` | | – | Substring match on assumed-role session names (repeatable) |
| `--service SERVICE` | `-s` | – | AWS service prefix, e.g. `ec2` (repeatable) |
| `--resource RESOURCE` | | – | Partial resource-name match |
| `--event-name EVENT` | `-e` | – | Specific API call, e.g. `RunInstances` (repeatable) |
| `--days N` | `-d` | `30` | Number of past days to analyse |
| `--start-time DATETIME` | | – | Start of window (ISO-8601), overrides `--days` |
| `--end-time DATETIME` | | – | End of window (ISO-8601), defaults to now |
| `--write-only` | | off | Exclude read-only API calls |
| `--errors-only` | | off | Only show events with API errors |
| `--max-results N` | | – | Cap the number of retrieved events |
| `--output FORMAT` | `-o` | `table` | `table` \| `json` \| `csv` |
| `--output-file FILE` | `-f` | – | Write output to file (useful with json/csv) |
| `--no-summary` | | off | Skip the summary panel |
| `--version` | | | Print version and exit |
| `--help` / `-h` | | | Show help and exit |

---

## Examples

### Investigate a specific IAM user (last 7 days)

```bash
python cloudtrail_analysis.py -u alice -d 7
```

### Check if `github_role` made any EC2 calls

```bash
python cloudtrail_analysis.py --role github_role --service ec2
```

### Detect any write actions by a deploy role, export to CSV

```bash
python cloudtrail_analysis.py \
  --role deploy_role \
  --write-only \
  --output csv \
  --output-file report.csv
```

### Show only failed calls for a specific user in a date range

```bash
python cloudtrail_analysis.py \
  -u alice \
  --start-time 2024-03-01 \
  --end-time 2024-03-31 \
  --errors-only
```

### Check all assumed-role sessions for `github_role` or `ci_role`, EC2 only

```bash
python cloudtrail_analysis.py \
  --role github_role \
  --role ci_role \
  --service ec2 \
  --days 14
```

### Use an SSO profile in a specific region, output JSON

```bash
aws sso login --profile prod-readonly

python cloudtrail_analysis.py \
  --profile prod-readonly \
  --region eu-central-1 \
  --role github_role \
  --output json \
  --output-file events.json
```

---

## Output formats

### `table` (default)

A colour-coded terminal table with an analysis summary panel.  Status /
progress messages are printed to **stderr** so the table on **stdout** can
be redirected cleanly.

```
╭─────────────────────────────────────────────────────────────────╮
│ CloudTrail Analysis – Summary                                   │
│ Total events : 42                                               │
│ Errors       : 3                                                │
│ Time range   : 2024-03-01 00:00:00 UTC  →  2024-03-31 23:59 UTC │
│ Services     : ec2 (38)  iam (4)                                │
│ Users / roles:                                                  │
│   arn:…:assumed-role/github_role/session (42 events)           │
╰─────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────────────────────────────╮
│ Time (UTC)           │ Username / Role │ Event          │ …    │
├──────────────────────┼─────────────────┼────────────────┼──────┤
│ 2024-03-28 14:22:01  │ github_role/…   │ RunInstances   │ …    │
│ 2024-03-27 09:10:55  │ github_role/…   │ DescribeVpcs   │ …    │
╰─────────────────────────────────────────────────────────────────╯
```

### `json`

A JSON array of event objects.  Status messages go to **stderr** so the
JSON on **stdout** is machine-readable:

```bash
python cloudtrail_analysis.py -u alice --output json 2>/dev/null | jq .
```

### `csv`

A CSV file with a header row.  Suitable for importing into spreadsheets or
SIEM tools:

```bash
python cloudtrail_analysis.py -u alice --output csv --output-file events.csv
```

---

## How it works

1. The tool calls the AWS CloudTrail `LookupEvents` API.
2. The most selective filter is pushed to the API (`Username` > `EventName` >
   `ResourceName`) to reduce network round-trips.
3. All remaining filters (roles, services, resources, write-only, errors-only)
   are applied locally after retrieval.
4. Results are rendered in the chosen output format.

> **Note:** CloudTrail `LookupEvents` only searches the last **90 days** of
> management events.  For longer retention or data events, configure a
> CloudTrail trail with S3 storage or use CloudTrail Lake.

---

## Development

```bash
# Install dev dependencies (adds pytest)
pip install -r requirements-dev.txt

# Run the test suite
python -m pytest tests/ -v
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ProfileNotFound` | Check the profile name with `aws configure list-profiles` |
| `NoCredentialsError` | Run `aws sso login --profile PROFILE` or set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| `AccessDenied` on `cloudtrail:LookupEvents` | Ask your AWS admin to grant the `cloudtrail:LookupEvents` permission |
| Empty results | Ensure CloudTrail is enabled in the target region; management events are logged by default |
| Results limited to 90 days | CloudTrail `LookupEvents` covers the last 90 days only; use a trail or CloudTrail Lake for longer history |
