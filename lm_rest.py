import os
import requests
import json
import time

def lm_rest(httpVerb: str, resourcePath: str, data: dict = None, queryParams: str = None):
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
    lm_subdomain = os.getenv('LM_SUBDOMAIN')
    lm_bearer_token = os.getenv('LM_BEARER_TOKEN')

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

