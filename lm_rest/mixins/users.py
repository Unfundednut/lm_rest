"""Users endpoints for LogicMonitorREST."""

from typing import Optional

from ..default_fields import DEFAULT_FIELDS


class UsersMixin:
    ## Get User Accounts
    def get_users(self, fields: Optional[list] = None, filter_expr: str = None, maxsize: int = None):
        path = f"{self.base_url}/setting/admins"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["users"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User Account
    def get_user(self, id, fields: Optional[list] = None, filter_expr: str = None):
        path = f"{self.base_url}/setting/admins/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["users"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=None,
        )

    ## Get API Tokens
    def get_api_tokens(
        self,
        fields: Optional[list] = None,
        filter_expr: str = None,
        type: str = None,
        maxsize=None,
    ):
        path = f"{self.base_url}/setting/admins/apitokens"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["api_tokens"]
        params = self._query_params(query_fields=fields, filter_expr=filter_expr)
        if type is not None and type.lower() == "bearer":
            params["type"] = "bearer"
        return self._query_get(
            query_path=path,
            query_params=params,
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User's API Tokens
    def get_api_user_tokens(
        self,
        id,
        fields: Optional[list] = None,
        filter_expr: str = None,
        type: str = None,
        maxsize=None,
    ):
        path = f"{self.base_url}/setting/admins/{str(id)}/apitokens"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["api_tokens"]
        params = self._query_params(query_fields=fields, filter_expr=filter_expr)
        if type is not None and type.lower() == "bearer":
            params["type"] = "bearer"
        return self._query_get(
            query_path=path,
            query_params=params,
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Access Groups
    def get_access_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/accessgroup"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get Access Group
    def get_access_group(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/accessgroup/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User Roles
    def get_user_roles(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/roles"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["user_roles"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User Role
    def get_user_role(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/roles/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = DEFAULT_FIELDS["user_roles"]
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User Role Groups
    def get_user_role_groups(self, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/role/groups"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Get User Role Group
    def get_user_role_group(self, id, fields: Optional[list] = None, filter_expr: str = None, maxsize=None):
        path = f"{self.base_url}/setting/role/groups/{str(id)}"
        size_limit = self.DEFAULT_PAGE_SIZE
        if fields is None:
            fields = []
        return self._query_get(
            query_path=path,
            query_params=self._query_params(query_fields=fields, filter_expr=filter_expr),
            size_limit=size_limit,
            max_size=maxsize,
        )

    ## Create User Role
    def post_user_role(self, payload: dict):
        path = f"{self.base_url}/setting/roles"
        return self._query_post(query_path=path, query_data=payload, query_params=None)

    ## Update User Role
    def patch_user_role(self, id, payload: dict):
        path = f"{self.base_url}/setting/roles/{str(id)}"
        return self._query_patch(query_path=path, query_data=payload, query_params=None)

