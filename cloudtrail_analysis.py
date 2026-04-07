#!/usr/bin/env python3
"""
AWS CloudTrail Analysis Tool

Analyze AWS CloudTrail logs to detect and report on user/role activity.
Supports filtering by users, roles, services, and resources.
"""

import csv
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

import boto3
import botocore.exceptions
import click
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# console for main (table) output to stdout
console = Console()
# status_console writes progress/informational messages to stderr so that
# JSON/CSV output sent to stdout stays machine-readable.
status_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------

def build_session(profile: Optional[str]) -> boto3.Session:
    """Return a boto3 Session, optionally scoped to an AWS named profile.

    Named profiles work for both long-term credentials and SSO profiles
    configured via ``aws configure sso``.  The caller only needs to ensure the
    profile is active (``aws sso login --profile <name>``) before running this
    tool.
    """
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_cloudtrail_client(profile: Optional[str], region: Optional[str]):
    """Return a CloudTrail boto3 client."""
    session = build_session(profile)
    kwargs: Dict[str, str] = {}
    if region:
        kwargs["region_name"] = region
    try:
        client = session.client("cloudtrail", **kwargs)
        # Eagerly verify the credentials are usable.
        client.get_trail_status  # noqa: B018 – attribute access only to validate
        return client
    except botocore.exceptions.ProfileNotFound as exc:
        raise click.ClickException(
            f"AWS profile '{profile}' not found. "
            "Run 'aws configure sso' or 'aws configure' to set it up."
        ) from exc
    except botocore.exceptions.NoCredentialsError as exc:
        raise click.ClickException(
            "No AWS credentials found. Configure credentials via environment "
            "variables, a credentials file, or an SSO profile."
        ) from exc


# ---------------------------------------------------------------------------
# Event retrieval
# ---------------------------------------------------------------------------

def _build_lookup_attributes(
    username: Optional[str],
    event_name: Optional[str],
    resource_name: Optional[str],
) -> List[Dict[str, str]]:
    """Return the best single LookupAttribute for the CloudTrail API.

    The API only accepts **one** attribute per request; additional filters are
    applied client-side after the results are fetched.
    """
    if username:
        return [{"AttributeKey": "Username", "AttributeValue": username}]
    if event_name:
        return [{"AttributeKey": "EventName", "AttributeValue": event_name}]
    if resource_name:
        return [{"AttributeKey": "ResourceName", "AttributeValue": resource_name}]
    return []


def fetch_events(
    client,
    start_time: datetime,
    end_time: datetime,
    username: Optional[str] = None,
    event_name: Optional[str] = None,
    resource_name: Optional[str] = None,
    max_results: Optional[int] = None,
) -> Iterator[Dict[str, Any]]:
    """Yield raw CloudTrail events, handling API pagination transparently.

    At most *max_results* events are yielded when that argument is set.
    """
    lookup_attrs = _build_lookup_attributes(username, event_name, resource_name)

    request: Dict[str, Any] = {
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": 50,
    }
    if lookup_attrs:
        request["LookupAttributes"] = lookup_attrs

    yielded = 0
    while True:
        try:
            response = client.lookup_events(**request)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise click.ClickException(f"AWS API error ({error_code}): {exc}") from exc

        for event in response.get("Events", []):
            if max_results is not None and yielded >= max_results:
                return
            yield event
            yielded += 1

        next_token = response.get("NextToken")
        if not next_token:
            break
        request["NextToken"] = next_token


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def matches_filters(
    event: Dict[str, Any],
    roles: Optional[Tuple[str, ...]],
    services: Optional[Tuple[str, ...]],
    resource_filter: Optional[str],
    event_names: Optional[Tuple[str, ...]],
    write_only: bool,
) -> bool:
    """Return *True* when *event* passes all supplied client-side filters."""

    # --- role filter ---
    # Assumed-role sessions appear as "arn:…:assumed-role/<RoleName>/<SessionName>"
    # or simply as "<RoleName>" in the Username field.
    if roles:
        raw_username = event.get("Username", "")
        if not any(role.lower() in raw_username.lower() for role in roles):
            return False

    # --- service filter ---
    # EventSource is e.g. "ec2.amazonaws.com"; match the prefix.
    if services:
        event_source = event.get("EventSource", "").lower()
        if not any(svc.lower() in event_source for svc in services):
            return False

    # --- specific event-name filter ---
    if event_names:
        if event.get("EventName") not in event_names:
            return False

    # --- resource name filter (partial, case-insensitive) ---
    if resource_filter:
        resources = event.get("Resources") or []
        matched = any(
            resource_filter.lower() in (r.get("ResourceName") or "").lower()
            for r in resources
        )
        if not matched:
            return False

    # --- write-only filter ---
    if write_only and event.get("ReadOnly") == "true":
        return False

    return True


# ---------------------------------------------------------------------------
# Event normalisation
# ---------------------------------------------------------------------------

def parse_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a raw CloudTrail API event into a simple dict for display."""
    ct: Dict[str, Any] = {}
    raw = event.get("CloudTrailEvent")
    if raw:
        try:
            ct = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass

    resources: List[Dict[str, str]] = event.get("Resources") or []
    resource_names = ", ".join(
        r.get("ResourceName", "") for r in resources if r.get("ResourceName")
    )
    resource_types = ", ".join(
        r.get("ResourceType", "") for r in resources if r.get("ResourceType")
    )

    event_time: Optional[datetime] = event.get("EventTime")

    return {
        "EventTime": event_time,
        "EventName": event.get("EventName", ""),
        "EventSource": event.get("EventSource", ""),
        "Username": event.get("Username", ""),
        "SourceIPAddress": ct.get("sourceIPAddress", ""),
        "UserAgent": ct.get("userAgent", ""),
        "Resources": resource_names,
        "ResourceTypes": resource_types,
        "ErrorCode": ct.get("errorCode", ""),
        "ErrorMessage": ct.get("errorMessage", ""),
        "Region": ct.get("awsRegion", ""),
        "ReadOnly": event.get("ReadOnly", ""),
        "EventId": event.get("EventId", ""),
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _short_service(event_source: str) -> str:
    """Strip the '.amazonaws.com' suffix for compact display."""
    return event_source.replace(".amazonaws.com", "")


def render_summary(events: List[Dict[str, Any]]) -> None:
    """Print a high-level summary panel to the console."""
    if not events:
        status_console.print(
            "[yellow]No events found matching the specified filters.[/yellow]"
        )
        return

    total = len(events)

    service_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}
    error_count = 0

    for e in events:
        src = _short_service(e.get("EventSource", "unknown"))
        service_counts[src] = service_counts.get(src, 0) + 1
        user = e.get("Username") or "unknown"
        user_counts[user] = user_counts.get(user, 0) + 1
        if e.get("ErrorCode"):
            error_count += 1

    times = [e["EventTime"] for e in events if e.get("EventTime")]
    time_range = ""
    if times:
        earliest = min(times)
        latest = max(times)
        fmt = "%Y-%m-%d %H:%M:%S UTC"
        if earliest.tzinfo:
            earliest_str = earliest.strftime(fmt)
            latest_str = latest.strftime(fmt)
        else:
            earliest_str = earliest.strftime("%Y-%m-%d %H:%M:%S")
            latest_str = latest.strftime("%Y-%m-%d %H:%M:%S")
        time_range = f"{earliest_str}  →  {latest_str}"

    top_services = sorted(service_counts.items(), key=lambda x: -x[1])
    services_str = "  ".join(f"{s} ({c})" for s, c in top_services[:8])

    top_users = sorted(user_counts.items(), key=lambda x: -x[1])
    users_str = "\n  ".join(f"{u} ({c} events)" for u, c in top_users[:10])

    lines = [
        f"[bold]Total events :[/bold] {total}",
        f"[bold]Errors       :[/bold] [red]{error_count}[/red]",
    ]
    if time_range:
        lines.append(f"[bold]Time range   :[/bold] {time_range}")
    lines.append(f"[bold]Services     :[/bold] {services_str}")
    lines.append(f"[bold]Users / roles:[/bold]\n  {users_str}")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold blue]CloudTrail Analysis – Summary[/bold blue]",
            border_style="blue",
            expand=False,
        )
    )


def render_table(events: List[Dict[str, Any]]) -> None:
    """Print events as a colourised Rich table."""
    table = Table(
        title="CloudTrail Events",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        show_lines=False,
        expand=True,
    )

    table.add_column("Time (UTC)", style="cyan", no_wrap=True, min_width=19)
    table.add_column("Username / Role", style="green", min_width=20)
    table.add_column("Event", style="yellow", min_width=20)
    table.add_column("Service", style="blue", min_width=12)
    table.add_column("Region", style="white", min_width=12)
    table.add_column("Resources", style="white", min_width=20)
    table.add_column("Source IP", style="white", min_width=15)
    table.add_column("Error", style="red", min_width=10)

    for e in events:
        error_code = e.get("ErrorCode", "")

        time_str = (
            e["EventTime"].strftime("%Y-%m-%d %H:%M:%S")
            if e.get("EventTime")
            else ""
        )
        error_str = error_code
        if e.get("ErrorMessage") and error_str:
            msg = e["ErrorMessage"]
            error_str = f"{error_code}: {msg[:60]}"

        row_style = "red" if error_str else ""

        table.add_row(
            time_str,
            escape(e.get("Username", "")),
            escape(e.get("EventName", "")),
            escape(_short_service(e.get("EventSource", ""))),
            escape(e.get("Region", "")),
            escape((e.get("Resources", "") or "")[:60]),
            escape(e.get("SourceIPAddress", "")),
            escape(error_str[:80]),
            style=row_style,
        )

    if table.row_count == 0:
        console.print("[yellow]No events to display.[/yellow]")
    else:
        console.print(table)


def format_as_json(events: List[Dict[str, Any]]) -> str:
    """Serialise events to a JSON string."""

    def default_serialiser(obj: Any) -> str:
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")

    return json.dumps(events, default=default_serialiser, indent=2)


_CSV_FIELDS = [
    "EventTime",
    "EventName",
    "EventSource",
    "Username",
    "SourceIPAddress",
    "UserAgent",
    "Resources",
    "ResourceTypes",
    "ErrorCode",
    "ErrorMessage",
    "Region",
    "ReadOnly",
    "EventId",
]


def format_as_csv(events: List[Dict[str, Any]]) -> str:
    """Serialise events to a CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=_CSV_FIELDS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for e in events:
        row = dict(e)
        if isinstance(row.get("EventTime"), datetime):
            row["EventTime"] = row["EventTime"].isoformat()
        writer.writerow(row)
    return output.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--profile", "-p",
    default=None,
    metavar="PROFILE",
    help=(
        "AWS named profile to use (supports SSO profiles). "
        "Run 'aws sso login --profile PROFILE' before using an SSO profile."
    ),
)
@click.option(
    "--region", "-r",
    default=None,
    metavar="REGION",
    help="AWS region to query (e.g. eu-central-1). Defaults to the profile/env default.",
)
@click.option(
    "--username", "-u",
    default=None,
    metavar="USERNAME",
    help=(
        "Filter events for this IAM username. "
        "This is the most efficient filter as it is pushed to the CloudTrail API."
    ),
)
@click.option(
    "--role",
    multiple=True,
    metavar="ROLE",
    help=(
        "Filter events matching this role name (substring match on the Username field). "
        "Can be specified multiple times to include multiple roles."
    ),
)
@click.option(
    "--service", "-s",
    multiple=True,
    metavar="SERVICE",
    help=(
        "Filter events for this AWS service prefix (e.g. ec2, s3, iam). "
        "Can be specified multiple times."
    ),
)
@click.option(
    "--resource",
    default=None,
    metavar="RESOURCE",
    help="Filter events that reference this resource name (partial, case-insensitive match).",
)
@click.option(
    "--event-name", "-e",
    multiple=True,
    metavar="EVENT",
    help=(
        "Filter for a specific API call name (e.g. RunInstances, PutObject). "
        "Can be specified multiple times."
    ),
)
@click.option(
    "--days", "-d",
    default=30,
    show_default=True,
    metavar="N",
    help="Number of past days to analyse (overridden by --start-time / --end-time).",
)
@click.option(
    "--start-time",
    default=None,
    metavar="DATETIME",
    help="Start of the time window (ISO-8601, e.g. 2024-01-15T00:00:00). Overrides --days.",
)
@click.option(
    "--end-time",
    default=None,
    metavar="DATETIME",
    help="End of the time window (ISO-8601). Defaults to now when --start-time is set.",
)
@click.option(
    "--write-only",
    is_flag=True,
    default=False,
    help="Exclude read-only API calls (Describe*, List*, Get*, etc.).",
)
@click.option(
    "--errors-only",
    is_flag=True,
    default=False,
    help="Only display events that resulted in an API error.",
)
@click.option(
    "--max-results",
    default=None,
    type=int,
    metavar="N",
    help="Maximum number of events to retrieve from CloudTrail.",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "csv"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-file", "-f",
    default=None,
    metavar="FILE",
    help="Write output to FILE instead of stdout (useful with --output json/csv).",
)
@click.option(
    "--no-summary",
    is_flag=True,
    default=False,
    help="Skip the summary panel (useful when piping output).",
)
@click.version_option(version="1.0.0", prog_name="cloudtrail_analysis")
def main(
    profile: Optional[str],
    region: Optional[str],
    username: Optional[str],
    role: Tuple[str, ...],
    service: Tuple[str, ...],
    resource: Optional[str],
    event_name: Tuple[str, ...],
    days: int,
    start_time: Optional[str],
    end_time: Optional[str],
    write_only: bool,
    errors_only: bool,
    max_results: Optional[int],
    output: str,
    output_file: Optional[str],
    no_summary: bool,
) -> None:
    """Analyse AWS CloudTrail logs and report on user / role activity.

    \b
    Examples:

      # Show all events for user 'alice' in the last 7 days
      cloudtrail_analysis.py -u alice -d 7

      # Check if role 'github_role' made any EC2 calls in the last 30 days
      cloudtrail_analysis.py --role github_role --service ec2

      # Write-only calls by any assumed role containing 'deploy', as CSV
      cloudtrail_analysis.py --role deploy --write-only --output csv -f report.csv

      # Use an SSO profile and check a specific resource
      cloudtrail_analysis.py --profile my-sso-profile --resource my-s3-bucket
    """
    # ------------------------------------------------------------------
    # Resolve time window
    # ------------------------------------------------------------------
    now = datetime.now(tz=timezone.utc)

    if start_time:
        try:
            resolved_start = datetime.fromisoformat(start_time)
            if resolved_start.tzinfo is None:
                resolved_start = resolved_start.replace(tzinfo=timezone.utc)
        except ValueError:
            raise click.BadParameter(
                f"Cannot parse '{start_time}' as ISO-8601 datetime.",
                param_hint="--start-time",
            )
        resolved_end = now
        if end_time:
            try:
                resolved_end = datetime.fromisoformat(end_time)
                if resolved_end.tzinfo is None:
                    resolved_end = resolved_end.replace(tzinfo=timezone.utc)
            except ValueError:
                raise click.BadParameter(
                    f"Cannot parse '{end_time}' as ISO-8601 datetime.",
                    param_hint="--end-time",
                )
    else:
        resolved_start = now - timedelta(days=days)
        resolved_end = now

    # ------------------------------------------------------------------
    # Validate input combinations
    # ------------------------------------------------------------------
    if not username and not role and not service and not resource and not event_name:
        status_console.print(
            "[yellow]Hint:[/yellow] No filters specified – fetching all events "
            f"from the last {days} days. This may be slow for busy accounts.\n"
        )

    # ------------------------------------------------------------------
    # Connect to AWS
    # ------------------------------------------------------------------
    status_console.print(
        f"[bold]Querying CloudTrail[/bold] "
        f"({resolved_start.strftime('%Y-%m-%d %H:%M')} UTC  →  "
        f"{resolved_end.strftime('%Y-%m-%d %H:%M')} UTC) …",
        highlight=False,
    )

    client = get_cloudtrail_client(profile, region)

    # ------------------------------------------------------------------
    # Fetch and filter events
    # ------------------------------------------------------------------
    # The CloudTrail API supports a single LookupAttribute; we push the most
    # selective one and apply the remaining filters client-side.
    primary_username = username  # may be None
    primary_event_name = event_name[0] if (event_name and not username) else None
    primary_resource = resource if (resource and not username and not primary_event_name) else None

    raw_events = fetch_events(
        client,
        start_time=resolved_start,
        end_time=resolved_end,
        username=primary_username,
        event_name=primary_event_name,
        resource_name=primary_resource,
        max_results=max_results,
    )

    parsed: List[Dict[str, Any]] = []
    for raw in raw_events:
        if not matches_filters(
            raw,
            roles=role if role else None,
            services=service if service else None,
            resource_filter=resource,
            event_names=event_name if event_name else None,
            write_only=write_only,
        ):
            continue
        parsed.append(parse_event(raw))

    # Apply errors-only filter across all output formats
    if errors_only:
        parsed = [e for e in parsed if e.get("ErrorCode")]

    status_console.print(
        f"[green]✓[/green] Retrieved [bold]{len(parsed)}[/bold] matching event(s).\n"
    )

    # ------------------------------------------------------------------
    # Render output
    # ------------------------------------------------------------------
    if output == "table":
        if not no_summary:
            render_summary(parsed)
        render_table(parsed)

    elif output == "json":
        text = format_as_json(parsed)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(text)
            status_console.print(f"[green]JSON written to {output_file}[/green]")
        else:
            click.echo(text)

    elif output == "csv":
        text = format_as_csv(parsed)
        if output_file:
            with open(output_file, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            status_console.print(f"[green]CSV written to {output_file}[/green]")
        else:
            click.echo(text, nl=False)


if __name__ == "__main__":
    main()
