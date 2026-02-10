"""Core client and request pipeline for LogicMonitorREST."""

import logging
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .mixins.alerts import AlertsMixin
from .mixins.collectors import CollectorsMixin
from .mixins.config_sources import ConfigSourcesMixin
from .mixins.dashboards import DashboardsMixin
from .mixins.datasources import DatasourcesMixin
from .mixins.devices import DevicesMixin
from .mixins.misc import MiscMixin
from .mixins.netscans import NetscansMixin
from .mixins.reports import ReportsMixin
from .mixins.users import UsersMixin


class BaseClient:
    DEFAULT_PAGE_SIZE = 1000

    def __init__(self, lm_info: Dict[str, str]) -> None:
        self.logger = logging.getLogger("lm_rest")
        self.subdomain: str = lm_info["subdomain"]
        self.bearer: str = lm_info["bearer"].replace("Bearer ", "")
        self.base_url: str = f"https://{self.subdomain}.logicmonitor.com/santaba/rest"
        self.headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.bearer}",
            "X-Version": "3",
        }
        self.session: requests.Session = requests.Session()
        self.session.headers.update(self.headers)
        # Number of remaining api calls to trigger sleep
        self.apiLimitBackoff: int = 5
        # Basic retry configuration for transient errors
        self.retries: int = 5
        self.timeout: int = int(lm_info.get("timeout", 30))
        retry = Retry(
            total=self.retries,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"}),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        test_creds = self._test_access()
        if test_creds is not True:
            raise ValueError(test_creds)

    def __str__(self):
        return f"lm_rest initlized for portal {self.subdomain}"

    def _test_access(self):
        test_call_path = f"{self.base_url}/alert/stat"
        self.logger.debug("Testing API access: %s", test_call_path)
        test_call = self.session.get(test_call_path, timeout=self.timeout)
        if test_call.status_code != 200:
            return {
                "error": f"Failed API Initilization: {test_call.status_code}, {test_call.text}"
            }
        return True

    def _query_params(self, query_fields, filter_expr):
        if isinstance(query_fields, list) and len(query_fields) > 0:
            query_fields = ",".join(query_fields)
        elif isinstance(query_fields, str) and query_fields:
            query_fields = query_fields
        else:
            query_fields = None

        if filter_expr is not None and filter_expr.startswith("?"):
            filter_expr = filter_expr[1:]

        params: Dict[str, str] = {}
        if query_fields is not None:
            params["fields"] = query_fields
        if filter_expr is not None:
            params["filter"] = filter_expr
        return params

    def _list_ints(self, items):
        return_list = []
        for item in items:
            try:
                return_list.append(int(item))
            except ValueError:
                print(f"Warning: {item} is not an int and was skipped")
        return return_list

    def _query_get(
        self,
        query_path,
        query_params,
        size_limit,
        max_size,
        no_pagination=False,
    ):
        return self._request(
            method="GET",
            url=query_path,
            params=query_params,
            paginate=not no_pagination,
            size_limit=size_limit,
            max_size=max_size,
        )

    def _query_post(self, query_path, query_data, query_params):
        return self._request(
            method="POST",
            url=query_path,
            params=query_params,
            json=query_data,
            paginate=False,
        )

    def _query_patch(self, query_path, query_data, query_params):
        return self._request(
            method="PATCH",
            url=query_path,
            params=query_params,
            json=query_data,
            paginate=False,
        )

    def _query_delete(self, query_path, query_params):
        return self._request(
            method="DELETE",
            url=query_path,
            params=query_params,
            paginate=False,
        )

    def _normalize_params(self, query_params):
        if query_params is None:
            return {}
        if isinstance(query_params, dict):
            return {k: v for k, v in query_params.items() if v is not None and v != ""}
        if isinstance(query_params, str):
            qp = query_params.lstrip("?")
            if qp == "":
                return {}
            parsed = parse_qs(qp, keep_blank_values=False)
            return {k: v[0] for k, v in parsed.items() if v}
        return {}

    def _parse_json(self, response: requests.Response):
        try:
            return response.json()
        except ValueError:
            self.logger.error(
                "Non-JSON response: status=%s body=%s",
                response.status_code,
                response.text,
            )
            raise ValueError(f"Non-JSON response: {response.status_code} {response.text}")

    def _maybe_sleep_rate_limit(self, response: requests.Response):
        try:
            api_remaining = int(response.headers.get("x-rate-limit-remaining", "0"))
            if api_remaining <= self.apiLimitBackoff:
                window = int(response.headers.get("x-rate-limit-window", "1"))
                self.logger.warning(
                    "Rate limit low: remaining=%s; sleeping=%ss",
                    api_remaining,
                    window,
                )
                time.sleep(window)
        except (TypeError, ValueError):
            return

    def _request(
        self,
        method: str,
        url: str,
        params=None,
        json=None,
        paginate: bool = False,
        size_limit: int = DEFAULT_PAGE_SIZE,
        max_size: Optional[int] = None,
    ):
        params = self._normalize_params(params)
        self.logger.debug(
            "Request start method=%s url=%s params=%s paginate=%s",
            method,
            url,
            params,
            paginate,
        )
        if not paginate:
            response = self.session.request(
                method, url, params=params, json=json, timeout=self.timeout
            )
            response.raise_for_status()
            self.logger.debug(
                "Request done method=%s url=%s status=%s",
                method,
                url,
                response.status_code,
            )
            return self._parse_json(response)

        count = 0
        items: List[Any] = []
        page_size = size_limit
        if max_size is not None and max_size < page_size:
            page_size = max_size

        while True:
            page_params = dict(params)
            page_params.update({"offset": count, "size": page_size})
            response = self.session.request(
                method, url, params=page_params, json=json, timeout=self.timeout
            )
            response.raise_for_status()
            self.logger.debug(
                "Page fetched method=%s url=%s status=%s offset=%s size=%s",
                method,
                url,
                response.status_code,
                count,
                page_size,
            )
            payload = self._parse_json(response)

            total = payload.get("total")
            if total is None:
                return payload
            if total == 0:
                return []

            page_items = payload.get("items", [])
            items.extend(page_items)
            count += len(page_items) if len(page_items) > 0 else page_size

            if max_size is not None and count >= max_size:
                return items[:max_size]

            if total < 0:
                if len(page_items) < page_size:
                    return items
            else:
                if count >= total:
                    return items

            self._maybe_sleep_rate_limit(response)

    def raw(
        self,
        httpVerb: str,
        resourcePath: str,
        data: dict = None,
        queryParams: Union[str, Dict[str, Any]] = None,
        paginate: bool = False,
        sizeLimit: int = DEFAULT_PAGE_SIZE,
        maxSize: Optional[int] = None,
    ):
        method = httpVerb.upper()
        if not resourcePath.startswith("/"):
            resourcePath = "/" + resourcePath
        url = f"{self.base_url}{resourcePath}"
        return self._request(
            method=method,
            url=url,
            params=queryParams,
            json=data,
            paginate=paginate,
            size_limit=sizeLimit,
            max_size=maxSize,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class LogicMonitorREST(
    BaseClient,
    UsersMixin,
    AlertsMixin,
    CollectorsMixin,
    ConfigSourcesMixin,
    DashboardsMixin,
    DatasourcesMixin,
    DevicesMixin,
    MiscMixin,
    NetscansMixin,
    ReportsMixin,
):
    pass
