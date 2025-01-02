# lm_rest
RESTful function for interacting with the LogicMonitor API.

## Setup
Import the class and initlize it
```python
from lm_rest_class import import LogicMonitorREST
import os
lm_cred_info = {
    'subdomain': os.getenv('PORTAL'),
    'bearer': os.getenv('BEARER')
}
lm_rest = LogicMonitorREST(lm_info=lm_cred_info)
```

1. Set `PORTAL` to the subdomain of your LogicMonitor portal.
2. Set `BEARER` to the generated bearer token from the LogicMonitor portal.
3. Install the required pip module `requests`.

## Example Usage
### Get 1 User

```python
tst_lm_users = lm_rest.get_users(maxsize=1)
print(json.dumps(tst_lm_users, indent=4))
```
Results in:
```json
[
    {
        "id": 34,
        "email": "johndoe@example.com",
        "username": "johndoe"
    }
]
```

### Chain Results
```python
network_team_accessgroup = lm_rest.get_access_groups(filter='name:"Network Team"')[0]['id']
network_datasources = lm_rest.get_datasources(filter='name~"Network_"')
for datasource in network_datasources:
    print(f"Updating {datasource['name']}")
    lm_rest.post_access_groups_mapping(moduletype="DATASOURCE",moduleid=datasource['id'],accessgroups=[network_team_accessgroup,1])
```

### Get all dead devices
```python
    lm_rest = LogicMonitorREST(lm_info={'subdomain': lm_info['subdomain'], 'bearer': lm_info['bearer_token']})
    lm_devices_raw = lm_rest.get_devices(fields=[],filter='hostStatus:"dead"')
```
# Basic Overview
I disliked the way the SDK worked and I would use a more simple version of this daily for work. I decieded to make it more indepth for our use case. I have a alot of defaults built in that can be overriden. Most of those will be found in the fields option for most calls. An exmaple of this is when you use `get_device` it will default to the following fields to return `['id','customProperties','displayName','hostStatus','inheritedProperties','name','systemProperties']`.


If you can't remember which properties it is you want, you simple change the call to `devices = lm_rest.get_device(deviceid, fields=[])`. When an empty list is pasted, it defaults to not sending the fields param so all fields are then returned.

