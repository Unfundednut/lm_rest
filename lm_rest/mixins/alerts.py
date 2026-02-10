"""Alerts endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class AlertsMixin:
    ## Get Alert Rules
    def get_alert_rules(self, fields: Optional[list] = None, filter_expr: str = None, maxsize: int = None):
        path = f"{self.base_url}/setting/alert/rules"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["alert_rules"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Alert Rule
    def get_alert_rule(self, id, fields: Optional[list] = None, filter_expr: str = None):
        path = f"{self.base_url}/setting/alert/rules/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["alert_rules"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get Alerts
    def get_alerts(self, fields: Optional[list] = None, filter_expr: str = None, maxsize: int = None):
        path = f"{self.base_url}/alert/alerts"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["alerts"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Alert
    def get_alert(self, id, fields: Optional[list] = None, filter_expr: str = None):
        path = f"{self.base_url}/alert/alerts/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["alerts"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get Alert Stats
    def get_alert_stats(self):
        path = f"{self.base_url}/alert/stat"
        size_limit = self.DEFAULT_PAGE_SIZE
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=[], filter_expr=None),
            size_limit=size_limit,
            max_size=None,
        )

