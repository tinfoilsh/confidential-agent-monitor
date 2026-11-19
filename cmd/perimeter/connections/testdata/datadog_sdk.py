"""Calls Datadog through the Perimeter test proxy with the official Python client.

Run by TestDatadogOfficialPythonClient; it prints the calls it made as JSON on its last line.
"""

import json
import os
import time

from datadog_api_client import ApiClient, Configuration
from datadog_api_client.exceptions import ApiException, ApiTypeError, ApiValueError
from datadog_api_client.v1.api.dashboards_api import DashboardsApi
from datadog_api_client.v1.api.events_api import EventsApi as EventsV1Api
from datadog_api_client.v1.api.metrics_api import MetricsApi as MetricsV1Api
from datadog_api_client.v1.api.monitors_api import MonitorsApi
from datadog_api_client.v1.model.event_create_request import EventCreateRequest
from datadog_api_client.v1.model.monitor import Monitor
from datadog_api_client.v1.model.monitor_type import MonitorType
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.api.metrics_api import MetricsApi
from datadog_api_client.v2.api.spans_api import SpansApi
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem
from datadog_api_client.v2.model.logs_list_request import LogsListRequest
from datadog_api_client.v2.model.logs_list_request_page import LogsListRequestPage
from datadog_api_client.v2.model.logs_query_filter import LogsQueryFilter
from datadog_api_client.v2.model.metric_intake_type import MetricIntakeType
from datadog_api_client.v2.model.metric_payload import MetricPayload
from datadog_api_client.v2.model.metric_point import MetricPoint
from datadog_api_client.v2.model.metric_series import MetricSeries
from datadog_api_client.v2.model.spans_list_request import SpansListRequest
from datadog_api_client.v2.model.spans_list_request_attributes import SpansListRequestAttributes
from datadog_api_client.v2.model.spans_list_request_data import SpansListRequestData
from datadog_api_client.v2.model.spans_list_request_type import SpansListRequestType
from datadog_api_client.v2.model.spans_query_filter import SpansQueryFilter

now = int(time.time())
calls = []


def run(site):
    configuration = Configuration()
    configuration.server_variables["site"] = site
    configuration.proxy = os.environ["DD_PROXY"]
    configuration.ssl_ca_cert = os.environ["DD_CA"]
    configuration.api_key["apiKeyAuth"] = os.environ["DD_API_KEY"]
    configuration.api_key["appKeyAuth"] = os.environ["DD_APP_KEY"]
    # The test upstream answers every call with the same small JSON document.
    configuration.check_return_type = False
    with ApiClient(configuration) as client:
        steps = [
            ("v1 list monitors", lambda: MonitorsApi(client).list_monitors(page_size=10)),
            ("v1 validate monitor", lambda: MonitorsApi(client).validate_monitor(
                Monitor(name="High CPU", type=MonitorType.METRIC_ALERT, query="avg(last_5m):avg:system.cpu.user{*} > 90", message="CPU high"))),
            ("v1 query metrics", lambda: MetricsV1Api(client).query_metrics(_from=now - 3600, to=now, query="avg:system.cpu.user{*}")),
            ("v1 list dashboards", lambda: DashboardsApi(client).list_dashboards()),
            ("v1 create event", lambda: EventsV1Api(client).create_event(EventCreateRequest(title="Deploy", text="web v42", tags=["env:test"]))),
            ("v2 search logs", lambda: LogsApi(client).list_logs(body=LogsListRequest(
                filter=LogsQueryFilter(query="service:web", _from="now-15m", to="now"), page=LogsListRequestPage(limit=5)))),
            ("v2 submit logs", lambda: LogsApi(client).submit_log(HTTPLog([HTTPLogItem(message="deployed", ddsource="agent", ddtags="env:test", service="web")]))),
            ("v2 submit metrics", lambda: MetricsApi(client).submit_metrics(MetricPayload(series=[MetricSeries(
                metric="agent.deploys", type=MetricIntakeType.COUNT, points=[MetricPoint(timestamp=now, value=1.0)])]))),
            ("v2 search spans", lambda: SpansApi(client).list_spans(SpansListRequest(data=SpansListRequestData(
                attributes=SpansListRequestAttributes(filter=SpansQueryFilter(query="service:web", _from="now-15m", to="now")),
                type=SpansListRequestType.SEARCH_REQUEST)))),
        ]
        for name, step in steps:
            try:
                step()
            except ApiException as e:
                raise SystemExit(f"{site} {name}: HTTP {e.status} {e.body!r}")
            except (ApiTypeError, ApiValueError):
                # The canned response need not deserialize; the Go test checks what was forwarded.
                pass
            calls.append({"site": site, "call": name})


for site in ["datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com", "ddog-gov.com"]:
    run(site)
print(json.dumps(calls))
