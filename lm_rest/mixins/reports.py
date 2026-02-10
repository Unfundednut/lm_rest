"""Reports endpoints for LogicMonitorREST."""

from typing import Optional


class ReportsMixin:
    ## Get Report Groups
    def get_report_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/report/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Create Report Folder
    def post_report_group(self, foldername: str):
        path = f"{self.base_url}/report/groups"
        payload = {"name": foldername}
        return self._query_post(query_path=path, query_data=payload, query_params=None)

