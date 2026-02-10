"""Dashboards endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class DashboardsMixin:
    ## Get Dashboard Groups
    def get_dashboard_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/dashboard/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["dashboard_groups"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Dashboard Group
    def get_dashboard_group(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/dashboard/groups/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["dashboard_groups"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Dashboards
    def get_dashboards(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/dashboard/dashboards"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["dashboards"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Dashboard
    def get_dashboard(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/dashboard/dashboards/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["dashboards"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Create Dashboard Folder
    def post_dashboard_group(self, payload: dict):
        path = f"{self.base_url}/dashboard/groups"
        return self._query_post(query_path=path, query_data=payload, query_params=None)

