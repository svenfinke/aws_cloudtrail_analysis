"""Unit tests for cloudtrail_analysis.py."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudtrail_analysis import (
    _build_lookup_attributes,
    fetch_events,
    format_as_csv,
    format_as_json,
    main,
    matches_filters,
    parse_event,
    render_summary,
    render_table,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_raw_event(
    username="alice",
    event_name="DescribeInstances",
    event_source="ec2.amazonaws.com",
    read_only="true",
    resources=None,
    error_code=None,
    error_message=None,
    region="eu-central-1",
):
    ct_inner = {
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.0",
        "awsRegion": region,
    }
    if error_code:
        ct_inner["errorCode"] = error_code
    if error_message:
        ct_inner["errorMessage"] = error_message

    return {
        "EventId": "abc-123",
        "EventName": event_name,
        "EventTime": datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        "EventSource": event_source,
        "Username": username,
        "ReadOnly": read_only,
        "Resources": resources or [],
        "CloudTrailEvent": json.dumps(ct_inner),
    }


# ---------------------------------------------------------------------------
# _build_lookup_attributes
# ---------------------------------------------------------------------------

class TestBuildLookupAttributes:
    def test_username_takes_priority(self):
        attrs = _build_lookup_attributes("alice", "RunInstances", "my-bucket")
        assert attrs == [{"AttributeKey": "Username", "AttributeValue": "alice"}]

    def test_event_name_used_when_no_username(self):
        attrs = _build_lookup_attributes(None, "RunInstances", "my-bucket")
        assert attrs == [{"AttributeKey": "EventName", "AttributeValue": "RunInstances"}]

    def test_resource_used_as_last_resort(self):
        attrs = _build_lookup_attributes(None, None, "my-bucket")
        assert attrs == [{"AttributeKey": "ResourceName", "AttributeValue": "my-bucket"}]

    def test_empty_when_no_filters(self):
        attrs = _build_lookup_attributes(None, None, None)
        assert attrs == []


# ---------------------------------------------------------------------------
# matches_filters
# ---------------------------------------------------------------------------

class TestMatchesFilters:
    def test_no_filters_always_matches(self):
        event = _make_raw_event()
        assert matches_filters(event, None, None, None, None, False)

    def test_role_filter_matches_substring(self):
        event = _make_raw_event(username="arn:aws:sts::123:assumed-role/github_role/session")
        assert matches_filters(event, ("github_role",), None, None, None, False)

    def test_role_filter_no_match(self):
        event = _make_raw_event(username="alice")
        assert not matches_filters(event, ("github_role",), None, None, None, False)

    def test_role_filter_case_insensitive(self):
        event = _make_raw_event(username="GITHUB_ROLE/session")
        assert matches_filters(event, ("github_role",), None, None, None, False)

    def test_service_filter_matches_prefix(self):
        event = _make_raw_event(event_source="ec2.amazonaws.com")
        assert matches_filters(event, None, ("ec2",), None, None, False)

    def test_service_filter_no_match(self):
        event = _make_raw_event(event_source="s3.amazonaws.com")
        assert not matches_filters(event, None, ("ec2",), None, None, False)

    def test_multiple_services_or_logic(self):
        event = _make_raw_event(event_source="s3.amazonaws.com")
        assert matches_filters(event, None, ("ec2", "s3"), None, None, False)

    def test_resource_filter_partial_match(self):
        event = _make_raw_event(
            resources=[{"ResourceName": "my-important-bucket", "ResourceType": "AWS::S3::Bucket"}]
        )
        assert matches_filters(event, None, None, "important", None, False)

    def test_resource_filter_no_match(self):
        event = _make_raw_event(
            resources=[{"ResourceName": "other-bucket", "ResourceType": "AWS::S3::Bucket"}]
        )
        assert not matches_filters(event, None, None, "important", None, False)

    def test_event_name_filter(self):
        event = _make_raw_event(event_name="RunInstances")
        assert matches_filters(event, None, None, None, ("RunInstances",), False)
        assert not matches_filters(event, None, None, None, ("TerminateInstances",), False)

    def test_write_only_excludes_read_only(self):
        event = _make_raw_event(read_only="true")
        assert not matches_filters(event, None, None, None, None, write_only=True)

    def test_write_only_keeps_write_events(self):
        event = _make_raw_event(read_only="false", event_name="RunInstances")
        assert matches_filters(event, None, None, None, None, write_only=True)

    def test_combined_filters_all_must_match(self):
        event = _make_raw_event(
            username="arn::assumed-role/deploy_role/ci",
            event_source="ec2.amazonaws.com",
            read_only="false",
        )
        assert matches_filters(
            event,
            roles=("deploy_role",),
            services=("ec2",),
            resource_filter=None,
            event_names=None,
            write_only=True,
        )

    def test_combined_filters_partial_fail(self):
        event = _make_raw_event(
            username="arn::assumed-role/deploy_role/ci",
            event_source="s3.amazonaws.com",  # wrong service
        )
        assert not matches_filters(
            event,
            roles=("deploy_role",),
            services=("ec2",),
            resource_filter=None,
            event_names=None,
            write_only=False,
        )


# ---------------------------------------------------------------------------
# parse_event
# ---------------------------------------------------------------------------

class TestParseEvent:
    def test_basic_fields_extracted(self):
        raw = _make_raw_event(
            username="alice",
            event_name="DescribeInstances",
            event_source="ec2.amazonaws.com",
            region="us-east-1",
        )
        parsed = parse_event(raw)
        assert parsed["Username"] == "alice"
        assert parsed["EventName"] == "DescribeInstances"
        assert parsed["EventSource"] == "ec2.amazonaws.com"
        assert parsed["SourceIPAddress"] == "1.2.3.4"
        assert parsed["Region"] == "us-east-1"

    def test_error_fields_extracted(self):
        raw = _make_raw_event(error_code="AccessDenied", error_message="Not authorised")
        parsed = parse_event(raw)
        assert parsed["ErrorCode"] == "AccessDenied"
        assert parsed["ErrorMessage"] == "Not authorised"

    def test_resource_names_joined(self):
        raw = _make_raw_event(
            resources=[
                {"ResourceName": "bucket-a", "ResourceType": "AWS::S3::Bucket"},
                {"ResourceName": "bucket-b", "ResourceType": "AWS::S3::Bucket"},
            ]
        )
        parsed = parse_event(raw)
        assert "bucket-a" in parsed["Resources"]
        assert "bucket-b" in parsed["Resources"]

    def test_invalid_cloudtrail_json_handled(self):
        raw = _make_raw_event()
        raw["CloudTrailEvent"] = "{not valid json"
        parsed = parse_event(raw)
        assert parsed["SourceIPAddress"] == ""

    def test_missing_cloudtrail_event_handled(self):
        raw = _make_raw_event()
        del raw["CloudTrailEvent"]
        parsed = parse_event(raw)
        assert parsed["SourceIPAddress"] == ""


# ---------------------------------------------------------------------------
# format_as_json / format_as_csv
# ---------------------------------------------------------------------------

class TestFormatAsJson:
    def test_returns_valid_json(self):
        events = [parse_event(_make_raw_event())]
        result = format_as_json(events)
        data = json.loads(result)
        assert isinstance(data, list)
        assert data[0]["EventName"] == "DescribeInstances"

    def test_datetime_serialised_as_iso(self):
        events = [parse_event(_make_raw_event())]
        result = format_as_json(events)
        assert "2024-03-01" in result


class TestFormatAsCsv:
    def test_returns_csv_with_header(self):
        events = [parse_event(_make_raw_event())]
        result = format_as_csv(events)
        lines = result.strip().splitlines()
        assert lines[0].startswith("EventTime")
        assert len(lines) == 2  # header + 1 row

    def test_event_name_in_csv(self):
        events = [parse_event(_make_raw_event(event_name="RunInstances"))]
        result = format_as_csv(events)
        assert "RunInstances" in result

    def test_multiple_events(self):
        events = [parse_event(_make_raw_event(event_name=f"Event{i}")) for i in range(5)]
        result = format_as_csv(events)
        lines = result.strip().splitlines()
        assert len(lines) == 6  # header + 5 rows


# ---------------------------------------------------------------------------
# fetch_events (mocked)
# ---------------------------------------------------------------------------

class TestFetchEvents:
    def _make_client(self, pages):
        """Return a mock CloudTrail client that yields the given pages."""
        client = MagicMock()
        responses = []
        for i, page in enumerate(pages):
            resp = {"Events": page}
            if i < len(pages) - 1:
                resp["NextToken"] = f"token-{i}"
            responses.append(resp)
        client.lookup_events.side_effect = responses
        return client

    def test_single_page(self):
        raw = [_make_raw_event()]
        client = self._make_client([raw])
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        events = list(fetch_events(client, start, end))
        assert len(events) == 1

    def test_multi_page(self):
        pages = [[_make_raw_event()] * 50, [_make_raw_event()] * 10]
        client = self._make_client(pages)
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        events = list(fetch_events(client, start, end))
        assert len(events) == 60

    def test_max_results_respected(self):
        pages = [[_make_raw_event()] * 50, [_make_raw_event()] * 50]
        client = self._make_client(pages)
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        events = list(fetch_events(client, start, end, max_results=30))
        assert len(events) == 30

    def test_username_lookup_attribute_sent(self):
        client = self._make_client([[]])
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        list(fetch_events(client, start, end, username="alice"))
        call_kwargs = client.lookup_events.call_args[1]
        assert call_kwargs["LookupAttributes"] == [
            {"AttributeKey": "Username", "AttributeValue": "alice"}
        ]

    def test_no_lookup_attribute_when_no_filters(self):
        client = self._make_client([[]])
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        list(fetch_events(client, start, end))
        call_kwargs = client.lookup_events.call_args[1]
        assert "LookupAttributes" not in call_kwargs

    def test_client_error_raises_click_exception(self):
        import botocore.exceptions

        client = MagicMock()
        client.lookup_events.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "LookupEvents",
        )
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 3, 31, tzinfo=timezone.utc)
        import click

        with pytest.raises(click.ClickException):
            list(fetch_events(client, start, end))


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

class TestCLI:
    """End-to-end tests that run the CLI via Click's test runner with mocked AWS."""

    def _mock_client(self, events):
        client = MagicMock()
        client.lookup_events.return_value = {"Events": events}
        return client

    def test_help_exits_zero(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output

    def test_version_exits_zero(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_table_output_default(self, mock_get_client):
        events = [_make_raw_event(username="alice", event_name="RunInstances")]
        mock_get_client.return_value = self._mock_client(events)

        runner = CliRunner()
        result = runner.invoke(main, ["-u", "alice", "-d", "7"])
        assert result.exit_code == 0
        assert "RunInstances" in result.output

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_json_output(self, mock_get_client):
        events = [_make_raw_event(username="alice")]
        mock_get_client.return_value = self._mock_client(events)

        # mix_stderr=False keeps status messages on stderr separate from the
        # JSON that goes to stdout, so we can parse result.output as JSON.
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["-u", "alice", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["Username"] == "alice"

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_csv_output(self, mock_get_client):
        events = [_make_raw_event(username="alice", event_name="PutObject")]
        mock_get_client.return_value = self._mock_client(events)

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["-u", "alice", "--output", "csv"])
        assert result.exit_code == 0
        lines = result.output.strip().splitlines()
        assert lines[0].startswith("EventTime")
        assert "PutObject" in result.output

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_write_only_flag_filters_read_events(self, mock_get_client):
        events = [
            _make_raw_event(event_name="DescribeInstances", read_only="true"),
            _make_raw_event(event_name="RunInstances", read_only="false"),
        ]
        mock_get_client.return_value = self._mock_client(events)

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main, ["-u", "alice", "--write-only", "--output", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        event_names = [e["EventName"] for e in data]
        assert "RunInstances" in event_names
        assert "DescribeInstances" not in event_names

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_service_filter(self, mock_get_client):
        events = [
            _make_raw_event(event_name="DescribeInstances", event_source="ec2.amazonaws.com"),
            _make_raw_event(event_name="ListBuckets", event_source="s3.amazonaws.com"),
        ]
        mock_get_client.return_value = self._mock_client(events)

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main, ["-u", "alice", "--service", "ec2", "--output", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all("ec2" in e["EventSource"] for e in data)
        assert len(data) == 1

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_role_filter(self, mock_get_client):
        events = [
            _make_raw_event(
                username="arn:aws:sts::123:assumed-role/github_role/session"
            ),
            _make_raw_event(username="alice"),
        ]
        mock_get_client.return_value = self._mock_client(events)

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main, ["--role", "github_role", "--output", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "github_role" in data[0]["Username"]

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_errors_only_flag(self, mock_get_client):
        events = [
            _make_raw_event(event_name="RunInstances", error_code="AccessDenied"),
            _make_raw_event(event_name="DescribeInstances"),
        ]
        mock_get_client.return_value = self._mock_client(events)

        # Use JSON output with mix_stderr=False so we can parse clean JSON
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main, ["-u", "alice", "--errors-only", "--output", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Only the event with an error should be returned
        assert len(data) == 1
        assert data[0]["ErrorCode"] == "AccessDenied"
        assert data[0]["EventName"] == "RunInstances"

    def test_invalid_start_time_gives_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--start-time", "not-a-date"])
        assert result.exit_code != 0
        assert "start-time" in result.output.lower() or "Error" in result.output

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_no_events_found_message(self, mock_get_client):
        mock_get_client.return_value = self._mock_client([])
        runner = CliRunner()
        result = runner.invoke(main, ["-u", "alice"])
        assert result.exit_code == 0
        assert "0" in result.output

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_json_written_to_file(self, mock_get_client, tmp_path):
        events = [_make_raw_event(username="alice")]
        mock_get_client.return_value = self._mock_client(events)

        out_file = tmp_path / "output.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["-u", "alice", "--output", "json", "--output-file", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert len(data) == 1

    @patch("cloudtrail_analysis.get_cloudtrail_client")
    def test_csv_written_to_file(self, mock_get_client, tmp_path):
        events = [_make_raw_event(username="alice")]
        mock_get_client.return_value = self._mock_client(events)

        out_file = tmp_path / "output.csv"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["-u", "alice", "--output", "csv", "--output-file", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        lines = out_file.read_text().strip().splitlines()
        assert lines[0].startswith("EventTime")
