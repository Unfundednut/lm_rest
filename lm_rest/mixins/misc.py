"""Misc endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class MiscMixin:
    ## Get AppliesTo Functions
    def get_appliesto_functions(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/functions"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["appliesto_functions"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=None),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get AppliesTo Function
    def get_appliesto_function(self, id, fields: Optional[list] = None, filter_expr: str = None):
        path = f"{self.base_url}/setting/functions/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["appliesto_functions"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=None),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get ApiPerfStats
    def get_api_perf_status(self):
        path = f"{self.base_url}/apiStats/externalApis"
        size_limit = 1
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=None, filter_expr=None),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get Audit Logs
    def get_audit_logs(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/accesslogs"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Undocumented appliesto functions call
    def get_functions(self, payload: dict):
        path = f"{self.base_url}/functions"
        return self._query_post(query_path=path, query_data=payload, query_params=None)

    ## Instance Datafetch
    def post_instance_datafetch(self, payload: dict, start_time: int, end_time: int, aggregate: str):
        path = f"{self.base_url}/device/instances/datafetch"
        query_string = f"start_time={start_time}&end_time={end_time}&aggregate={aggregate}"
        return self._query_post(query_path=path, query_data=payload, query_params=query_string)

    ## Create Access Group Mapping | Default accessgroups to 1, the default access group in LM
    def post_access_groups_mapping(self, moduletype: str, moduleid: int, accessgroups=None):
        path = f"{self.base_url}/setting/accessgroup/mapunmap/modules"
        if accessgroups is None:
            accessgroups = [1]
        payload = {
            "mappingDetails": [
                {
                    "accessgroups": self._list_ints(accessgroups),
                    "moduletype": moduletype,
                    "moduleid": int(moduleid),
                }
            ]
        }
        return self._query_post(query_path=path, query_data=payload, query_params=None)

