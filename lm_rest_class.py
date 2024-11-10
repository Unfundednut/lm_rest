import requests
import time
import json

class lm_rest:
    """lm_rest class
        Initilize: lm_rest = lm_rest(lm_info={'subdomain': 'acmecorp', 'bearer': 'lmb_ANABDJAJD'})
        Example Call: lm_users = lm_rest.get_users()
    """

    def __init__(self, lm_info: dict):
        self.subdomain = lm_info['subdomain']
        self.bearer = lm_info['bearer'].replace('Bearer ','')
        self.base_url = f'https://{self.subdomain}.logicmonitor.com/santaba/rest'
        self.headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {self.bearer}', 'X-Version': '3'}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        # Number of remaining api calls to trigger sleep
        self.apiLimitBackoff = 5
        # TODO: Build in retries
        self.retries = 5
        testCreds = self.__testAccess()
        if testCreds is not True:
            raise ValueError(testCreds)

        self.workflows = self.Workflows(self)

    def __str__(self):
        return f'lm_rest initlized for portal {self.subdomain}'

    # Internal Functions
    ## Test API Creds
    def __testAccess(self):
        testCallPath = f'{self.base_url}/alert/stat'
        testCall = self.session.get(testCallPath)
        if testCall.status_code != 200:
            return {"error": f"Failed API Initilization: {testCall.status_code}, {testCall.text}"}
        else:
            return True

    ## Handle Query Params, Fields and Filters
    def __queryParams(self, queryFields, queryFilter):
        if isinstance(queryFields,list) and len(queryFields) > 0:
            queryFields = ','.join(queryFields)
        else:
            queryFields = None

        if queryFilter is not None:
            if queryFilter.startswith('?'):
                queryFilter = queryFilter[1:]

        if queryFields is not None and queryFilter is not None:
            queryParams = f'fields={queryFields}&filter={queryFilter}'
        elif queryFields is not None and queryFilter is None:
            queryParams =  f'fields={queryFields}'
        elif queryFields is None and queryFilter is not None:
            queryParams = f'filter={queryFilter}'
        else:
            queryParams = ""
        return queryParams

    ## Handle lists of numbers to verify they are numbers and not letters
    def __listints(self, list):
        returnList = []
        for item in list:
            try:
                returnList.append(int(item))
            except ValueError:
                print(f"Warning: {item} is not an int and was skipped")
        return returnList

    ## Generic get for all future gets
    def __queryGet(self, queryPath, queryParams, sizeLimit, maxSize):
        count = 0
        returnList = []
        if maxSize is not None and maxSize < sizeLimit:
            sizeLimit = maxSize
        while True:
            queryParamsPagination = f'?{queryParams}&offset={count}&size={sizeLimit}'
            queryURL = f'{queryPath}{queryParamsPagination}'
            queryResponse = self.session.get(queryURL)
            # Get Response Total, if the total field doesn't exist, assume a single item respoonse
            queryResponseTotal = queryResponse.json().get('total', 'NoTotal')
            if queryResponseTotal == 'NoTotal':
                queryResponseItems = queryResponse.json()
                return queryResponseItems
            else:
                queryResponseItems = queryResponse.json()['items']
            queryResponseItemsSize = len(queryResponseItems)
            # Alerts use negative totals
            if queryResponseItemsSize > 0:
                count += queryResponseItemsSize
            else:
                count += sizeLimit
            returnList = returnList + queryResponseItems
            if count >= queryResponseTotal and queryResponseTotal > 0:
                return returnList
            elif maxSize is not None and count >= maxSize:
                return returnList
            elif queryResponseTotal == 0:
                return False
            else:
                queryResponseHeaders = queryResponse.headers
                api_limit = int(queryResponseHeaders['x-rate-limit-limit'])
                api_remaining = int(queryResponseHeaders['x-rate-limit-remaining'])
                if api_remaining <= self.apiLimitBackoff:
                    time.sleep(int(queryResponseHeaders['x-rate-limit-window']))

    ## Generic post for all future posts
    def __queryPost(self, queryPath, queryData, queryParams):
        if queryParams is not None:
            if not queryParams.startswith('?'):
                queryParams = f'?{queryParams}'
            queryURL = f'{queryPath}{queryParams}'
        else:
            queryURL = queryPath
        queryResponse = self.session.post(url=queryURL,json=queryData)
        queryResponseItems = queryResponse.json()
        return queryResponseItems


    class Workflows:
        """Workflows class
            This contains all custom workflows that require multiple calls to accomplish standard items
            Example Call: lm_rest.workflows.create_client(companyid="ACMEC001")
        """
        def __init__(self,lm_rest):
            self.lm_rest = lm_rest

        def create_client(self,companyid):
            print(f"Creating {companyid} | {self.lm_rest.base_url}")
            return companyid

    # Get Calls
    ## Get User Accounts
    def get_users(self, fields: list = ['id','username','email'], filter: str = None, maxsize: int = None):
        path = f'{self.base_url}/setting/admins'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmUsers = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmUsers

    ## Get User Account
    def get_user(self, id, fields: list = ['id','username','email'], filter: str = None):
        path = f'{self.base_url}/setting/admins/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmUser = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmUser

    ## Get Alert Rules
    def get_alert_rules(self, fields: list = ['id','name','priority','levelStr','escalationChainId'], filter: str = None, maxsize: int = None):
        path = f'{self.base_url}/setting/alert/rules'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmAlertRules = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmAlertRules

    ## Get Alert Rule
    def get_alert_rule(self, id, fields: list = ['id','name','priority','levelStr','escalationChainId'], filter: str = None):
        path = f'{self.base_url}/setting/alert/rules/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmAlertRule = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmAlertRule

    ## Get Alerts
    def get_alerts(self, fields: list = ['id','resourceId','instanceName','type','internalId','tenant','monitorObjectName','startEpoch','severity','tenant'], filter: str = None, maxsize: int = None):
        path = f'{self.base_url}/alert/alerts'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmAlerts = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmAlerts
    
    ## Get Alert
    def get_alert(self, id, fields: list = ['resourceId','instanceName','type','internalId','tenant','monitorObjectName','startEpoch','severity','tenant'], filter: str = None):
        path = f'{self.base_url}/alert/alerts/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        lmAlert = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmAlert

    ## Get Alert Stats
    def get_alert_stats(self):
        path = f'{self.base_url}/alert/stat'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=[],queryFilter=None)
        lmAlertStats = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmAlertStats

    ## Get API Tokens
    def get_api_tokens(self, fields: list = ['id','adminId','status','lastUsedOn','accessId','adminName'], filter: str = None, type: str = None, maxsize = None):
        path = f'{self.base_url}/setting/admins/apitokens'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        if type is not None and type.lower() == 'bearer':
            queryParams = queryParams + '&type=bearer'
        lmApiTokens = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmApiTokens

    ## Get User's API Tokens
    def get_api_user_tokens(self, id, fields: list = ['id','adminId','status','lastUsedOn','accessId','adminName'], filter: str = None, type: str = None, maxsize = None):
        path = f'{self.base_url}/setting/admins/{str(id)}/apitokens'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields, queryFilter=filter)
        if type is not None and type.lower() == 'bearer':
            queryParams = queryParams + '&type=bearer'
        lmApiTokens = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit, maxSize=maxsize)
        return lmApiTokens

    ## Get AppliesTo Functions
    def get_appliesto_functions(self, fields: list = ['id','code','description','name'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/functions'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=None)
        lmAppliesToFunctions = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit, maxSize=maxsize)
        return lmAppliesToFunctions

    ## Get AppliesTo Function
    def get_appliesto_function(self, id, fields: list = ['id','code','description','name'], filter: str = None):
        path = f'{self.base_url}/setting/functions/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=None)
        lmAppliesToFunction = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmAppliesToFunction
    
    ## Get ApiPerfStats
    def get_api_perf_status(self):
        path = f'{self.base_url}/apiStats/externalApis'
        sizeLimit = 1
        queryParams = self.__queryParams(queryFields=None,queryFilter=None)
        lmApiPerfStats = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmApiPerfStats
    
    ## Get Audit Logs
    def get_audit_logs(self, format: str = 'json', fields: list = [], filter: str = None, maxsize=None):
        path = f'{self.base_url}/setting/accesslogs'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmAuditLogs = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmAuditLogs

    ## Get Collector Groups
    def get_collector_groups(self, fields: list = ['id','name','numOfCollectors'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/collector/groups'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmCollectorGroups = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmCollectorGroups

    ## Get Collector Group
    def get_collector_group(self, id, fields: list = [], filter: str = None):
        path = f'{self.base_url}/setting/collector/groups/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmCollectorGroups = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=None)
        return lmCollectorGroups

    ## Get Collectors
    def get_collectors(self, fields: list = ['customProperties','ea','arch','collectorSize','isLmlogsSyslogEnabled','collectorGroupName','collectorGroupId','numberOfHosts','numberOfInstances','hostname','platform','id'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/collector/collectors'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmCollectors = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmCollectors

    ## Get Collector
    def get_collector(self, id, fields: list = ['customProperties','ea','arch','collectorSize','isLmlogsSyslogEnabled','collectorGroupName','collectorGroupId','numberOfHosts','numberOfInstances','hostname','platform','id'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/collector/collectors/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmCollector = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmCollector

    ## Get Collector Versions
    def get_collector_versions(self, fields: list = [], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/collector/collectors/versions'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmCollectorVersions = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmCollectorVersions

    ## Get Access Groups
    def get_access_groups(self, fields: list = [], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/accessgroup'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmAccessGroups = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmAccessGroups

    ## Get Access Group
    def get_access_group(self, id, fields: list = [], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/accessgroup/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmAccessGroup = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmAccessGroup

    ## Get Config Sources
    def get_config_sources(self, fields: list = ['id','name','displayName'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/configsources'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmConfigSources = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmConfigSources

    ## Get Config Source
    def get_config_source(self, id, fields: list = ['id','name','displayName'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/configsources/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmConfigSource = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmConfigSource

    ## Get Dashboard Groups
    def get_dashboard_groups(self, fields: list = ['id','name','numOfDashboards','numOfDirectDashboards','numOfDirectSubGroups','parentId'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/dashboard/groups'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDashboardGroups = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDashboardGroups

    ## Get Dashboard Group
    def get_dashboard_group(self, id, fields: list = ['id','name','numOfDashboards','numOfDirectDashboards','numOfDirectSubGroups','parentId'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/dashboard/groups/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDashboardGroup = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDashboardGroup

    ## Get Dashboards
    def get_dashboards(self, fields: list = ['id','fullName','groupFullPath','groupId','groupName','name'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/dashboard/dashboards'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDashboards = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDashboards

    ## Get Dashboard
    def get_dashboard(self, id, fields: list = ['id','fullName','groupFullPath','groupId','groupName','name'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/dashboard/dashboards/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDashboard = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDashboard
    
    ## Get Datasources
    def get_datasources(self, fields: list = ['id','collectInterval','collectMethod','description','displayName','hasMultiInstances','name','tags'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/datasources'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDatasources = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDatasources

    ## Get Datasource
    def get_datasource(self, id, fields: list = ['id','collectInterval','collectMethod','description','displayName','hasMultiInstances','name','tags'], filter: str = None, maxsize = None):
        path = f'{self.base_url}/setting/datasources/{str(id)}'
        sizeLimit = 1000
        queryParams = self.__queryParams(queryFields=fields,queryFilter=filter)
        lmDatasource = self.__queryGet(queryPath=path,queryParams=queryParams,sizeLimit=sizeLimit,maxSize=maxsize)
        return lmDatasource


    # POST Calls
    ## Create Access Group Mapping
    def post_access_groups_mapping(self, moduletype: str, moduleid: int, accessgroups: list = [1]):
        path = f'{self.base_url}/setting/accessgroup/mapunmap/modules'
        payload = {"mappingDetails": [{"accessgroups": self.__listints(accessgroups),"moduletype": moduletype,"moduleid": int(moduleid)}]}
        lmAccessGroupMappings = self.__queryPost(queryPath=path,queryData=payload,queryParams=None)
        return lmAccessGroupMappings
        
    ## Raw Request
    def rest_raw(self, httpVerb: str, resourcePath: str, data: dict = None, queryParams: str = None):
        """Used to easily interact with LogicMonitor v3 API

        Args:
            httpVerb (str): HTTP Method - GET, PUT, POST, PATCH or DELETE
            resourcePath (str): Resource path for API
            data (str): json formatted string for PUT, POST or PATCH
            queryParams (str): filter and field parameters

        Returns:
            list: For multiple devices/groups return
            dict: For single device/group return
        """

        # Which HTTP Methods are allowed
        validverbs = {'GET', 'PUT', 'POST', 'PATCH', 'DELETE'}

        # Which HTTP Methods require the data variable
        dataverbs = {'PUT', 'POST', 'PATCH'}

        # IF the HTTP Method supplied isn't in the list of allowed
        if httpVerb not in validverbs:
            raise ValueError("httpVerb must be one of %r." % validverbs)
        
        # If the data variable is not set and is required
        if httpVerb in dataverbs and not data:
            raise ValueError("data must not be empty")

        # Get environment variables needed
        lm_subdomain = self.subdomain
        lm_bearer_token = self.bearer

        # Raise exception if not set
        if not lm_subdomain:
            raise ValueError("Environment Variable: LM_SUBDOMAIN must be set!")
        if not lm_bearer_token:
            raise ValueError("Environment Variable: LM_BEARER_TOKEN must be set!")
        
        # Build Headers
        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {lm_bearer_token}', 'X-Version': '3'}

        # Initialize variables
        count = 0
        done = 0
        allitems = []

        # If queryParams isn't initilized or initilized properly add ? in front
        if queryParams is not None and not queryParams.startswith("?"):
            queryParams = "?" + queryParams
        elif queryParams is None:
            queryParams = "?"
        
        while done == 0:
            # Convery the dict to a str
            data = json.dumps(data)
            # Use offset to paginate results
            queryParamsPagination = '&offset='+str(count)+'&size=1000'

            # Make request and check for errors
            if httpVerb == 'PUT':
                try:
                    url = 'https://' + lm_subdomain + '.logicmonitor.com/santaba/rest' + resourcePath + queryParams
                    response = requests.put(url, data=data, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    raise SystemExit(err)
            elif httpVerb == 'POST':
                try:
                    url = 'https://' + lm_subdomain + '.logicmonitor.com/santaba/rest' + resourcePath + queryParams
                    response = requests.post(url, data=data, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    raise SystemExit(err)
            elif httpVerb == 'PATCH':
                try:
                    url = 'https://' + lm_subdomain + '.logicmonitor.com/santaba/rest' + resourcePath + queryParams
                    response = requests.patch(url, data=data, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    raise SystemExit(err)
            elif httpVerb == 'DELETE':
                try:
                    url = 'https://' + lm_subdomain + '.logicmonitor.com/santaba/rest' + resourcePath
                    response = requests.delete(url, data=data, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    raise SystemExit(err)
            else:
                try:
                    url = 'https://' + lm_subdomain + '.logicmonitor.com/santaba/rest' + resourcePath + queryParams + queryParamsPagination
                    response = requests.get(url, data=data, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    raise SystemExit(err)

            if httpVerb != 'GET':
                parsed = json.loads(response.content)
                lm_return = parsed
                break
            else:
                # If a GET parse content get totals
                parsed = json.loads(response.content)
                total = parsed.get('total', 0)
                if total != 0:
                    items = parsed['items']
                else:
                    lm_return = parsed
                    done = 1
                    break
                allitems = allitems + items
                numitems = len(items)
                count += numitems
                if count == total:
                    done = 1
                    lm_return = allitems
                else:
                    # Loop and check if we are rate limited
                    returned_headers = response.headers
                    api_limit = int(returned_headers['x-rate-limit-limit'])
                    api_left = int(returned_headers['x-rate-limit-remaining'])
                    api_threshold = api_limit - api_left
                    if api_threshold > 5:
                        time.sleep(int(returned_headers['x-rate-limit-window']))

        return lm_return

