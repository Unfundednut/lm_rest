"""Devices endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class DevicesMixin:
    ## Get Devices
    def get_devices(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/devices"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["devices"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device
    def get_device(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/devices/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["devices"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    # Get Device Datasources
    def get_device_datasources(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/devices/{str(id)}/devicedatasources"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["device_datasources"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    # Get Device Datasource Instances
    def get_device_datasource_instances(
        self, id, datasourceid, fields: Optional[list] = None, filter_expr: str = None, maxsize=None
    ):
        path = f"{self.base_url}/device/devices/{str(id)}/devicedatasources/{str(datasourceid)}/instances"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    # Get Device Datasource Instance Config
    def get_device_datasource_instance_config(
        self,
        id,
        datasourceid,
        instanceid,
        fields: Optional[list] = None,
        filter_expr: str = None,
        maxsize=None,
    ):
        path = f"{self.base_url}/device/devices/{str(id)}/devicedatasources/{str(datasourceid)}/instances/{str(instanceid)}/config"
        size_limit = 50
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Groups
    def get_device_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["device_groups"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group
    def get_device_group(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["device_group"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group Properties
    def get_device_group_properties(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups/{str(id)}/properties"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group Property
    def get_device_group_property(
        self, id, fieldname, fields: Optional[list] = None, filter_expr: str = None, maxsize=None
    ):
        path = f"{self.base_url}/device/groups/{str(id)}/properties/{fieldname}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group Datasources
    def get_device_group_datasources(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups/{str(id)}/datasources"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group Datasource
    def get_device_group_datasource(
        self, id, dsid, fields: Optional[list] = None, filter_expr: str = None, maxsize=None
    ):
        path = f"{self.base_url}/device/groups/{str(id)}/datasources/{str(dsid)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## GET Device Group SDTs
    def get_device_group_sdts(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups/{str(id)}/historysdts"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Group Alerts
    def get_device_group_alerts(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/device/groups/{str(id)}/alerts"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["device_group_alerts"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Device Datasource Instance Alert Settings
    def get_device_datasource_instance_alert_settings(
        self, deviceid, devicedatasourceid, instanceid, fields: Optional[list] = None, filter_expr: str = None, maxsize=None
    ):
        path = f"{self.base_url}/device/devices/{str(deviceid)}/devicedatasources/{str(devicedatasourceid)}/instances/{str(instanceid)}/alertsettings"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Create Resource Folder
    def post_device_group(self, payload: dict):
        path = f"{self.base_url}/device/groups"
        return self._query_post(query_path=path, query_data=payload, query_params=None)

    ## Update Resource Folder
    def patch_device_group(self, id, payload: dict):
        path = f"{self.base_url}/device/groups/{str(id)}"
        return self._query_patch(query_path=path, query_data=payload, query_params=None)

    ## Update Device Datasource Instance Threshold
    def patch_device_datasource_instance_threshold(
        self, deviceid, devicedatasourceid, instanceid, alertid, payload: dict
    ):
        path = f"{self.base_url}/device/devices/{str(deviceid)}/devicedatasources/{str(devicedatasourceid)}/instances/{str(instanceid)}/alertsettings/{alertid}"
        return self._query_patch(query_path=path, query_data=payload, query_params=None)

