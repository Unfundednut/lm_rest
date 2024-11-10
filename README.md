# lm_rest
RESTful function for interacting with the LogicMonitor API.

## Setup
Import the class and initlize it
```python
from lm_rest_class import lm_rest
import os
lm_cred_info = {
    'subdomain': os.getenv('PORTAL'),
    'bearer': os.getenv('BEARER')
}
lm_rest = lm_rest(lm_info=lm_cred_info)
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