# lm_rest
RESTful function for interacting with the LogicMonitor API.

## Setup
Have the following environment variables set.
```shell
LM_SUBDOMAIN=""
LM_BEARER_TOKEN=""
```

1. Set `LM_SUBDOMAIN` to the subdomain of your LogicMonitor portal.
2. Set `LM_BEARER_TOKEN` to the generated one from LogicMonitor.
3. Install the required pip module `requests` or simply run a `pip install -r requirements.txt`

## Examples
### Get resources in a folder

```python
resources = lm_rest('GET', '/device/groups/27770/devices', '', '?fields=name,id')
for resource in resources:
    resource_name = resource['name']
    resource_id = resource['id']
    # Do more stuff
```

### Update a property on a resource

```python
deviceid = "5653"
lm_rest_path = '/device/devices/' + deviceid
lm_rest_data = '{"customProperties":[{"name":"testprop","value":"Prod"}]}'
lm_rest_queryparams = '?patchFields=customProperties&opType=replace'
lm_result = lm_rest('PATCH', lm_rest_path, lm_rest_data, lm_rest_queryparams)
```

### Chain Results
```python
devices = lm_rest('GET', '/device/groups/27680/devices', '', '?fields=name,id')
for device in devices:
    lm_rest_path = '/device/devices/' + str(device['id'])
    lm_rest_data = '{"customProperties":[{"name":"testprop","value":"Prod"}]}'
    lm_rest_queryparams = '?patchFields=customProperties&opType=replace'
    lm_result = lm_rest('PATCH', lm_rest_path, lm_rest_data, lm_rest_queryparams)
    print(json.dumps(lm_result, indent=4))
```