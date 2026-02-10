"""Collectors endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class CollectorsMixin:
    ## Get Collector Groups
    def get_collector_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/collector/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["collector_groups"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Collector Group
    def get_collector_group(self, id, fields: Optional[list] = None, filter_expr: str = None):
        path = f"{self.base_url}/setting/collector/groups/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get Collectors
    def get_collectors(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/collector/collectors"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["collectors"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Collector
    def get_collector(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/collector/collectors/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["collectors"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Collector Debug Session
    def get_collector_debug_session(self, collectorid, sessionid):
        path = f"{self.base_url}/debug/{str(sessionid)}"
        return self._query_get(
            query_path=path,
            query_params="collectorId=" + str(collectorid),
            size_limit=None,
            max_size=None,
            no_pagination=True,
        )

    ## Get Collector Versions
    def get_collector_versions(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/collector/collectors/versions"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Create Collector Group
    def post_collector_group(self, payload: dict):
        path = f"{self.base_url}/setting/collector/groups"
        return self._query_post(query_path=path, query_data=payload, query_params=None)

    ## Execute Collector Debug Command
    def post_collector_debug_command(self, collectorid, debugcommand):
        path = f"{self.base_url}/debug"
        payload = {"cmdline": debugcommand}
        return self._query_post(
            query_path=path,
            query_data=payload,
            query_params="collectorId=" + str(collectorid),
        )

