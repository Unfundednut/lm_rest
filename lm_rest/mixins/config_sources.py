"""Config Sources endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class ConfigSourcesMixin:
    ## Get Config Sources
    def get_config_sources(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/configsources"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["config_sources"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Config Source
    def get_config_source(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/configsources/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["config_sources"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

