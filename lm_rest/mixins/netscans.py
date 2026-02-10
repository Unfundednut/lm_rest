"""Netscans endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class NetscansMixin:
    ## Get Netscans
    def get_netscans(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/netscans"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["netscans"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Netscan
    def get_netscan(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/netscans/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["netscans"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Netscan Groups
    def get_netscan_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/netscans/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Delete Netscan
    def delete_netscan(self, id):
        path = f"{self.base_url}/setting/netscans/{str(id)}"
        return self._query_delete(query_path=path, query_params=None)

    ## Delete Netscan Group
    def delete_netscan_group(self, id):
        path = f"{self.base_url}/setting/netscans/groups/{str(id)}"
        return self._query_delete(query_path=path, query_params=None)

