# HTTP DDoS detector 
This repository contains an ONOS application that is focused to detect and mitigate HTTP DDoS attacks.

## Processing packets into flows
TODO

## Detecting malicious flows
TODO

## Mitigating attacks
You can access the onos api docs through the following url http://192.168.99.124:8181/onos/v1/docs/ in there check the flow api to access the endpoints that will add or delete flow rules. For more info on flow rules check the wiki https://wiki.onosproject.org/display/ONOS/Flow+Rules. 

In order to block the attacker we will use the following criteria on the flow rule:

- IP_PROTO	Ip protocol	uint16 (0x06 TCP)
- TCP_DST	match port	int64 (the attacked host port)
- IPV4_SRC	source ip	string (the attacker host ip)
- IPV4_DST	destination ip	string (the attacked host ip)

To drop the matched packets we will leave empty the treatment property of the flow, so the JSON object required to add the flow rule will be:

```
{
  "flows": [
    {
      "priority": 40000,
      "timeout": 0,
      "isPermanent": true,
      "deviceId": "of:0000000000000001",
    // Leave treatment empty to drop the package
    // "treatment": {},
      "selector": {
        "criteria": [
          {
            "type": "IP_PROTO",
            "protocol": "0x06"
          },
          {
            "type": "TCP_DST",
            "tcpPort": 80
          },
          {
            "type": "IPV4_SRC",
            "ip": "192.168.1.2/24"
          },
          {
            "type": "IPV4_DST",
            "ip": "192.168.1.1/24"
          }
        ]
      }
    }
  ]
}
```

- run simple server on host `python -m SimpleHTTPServer 80`
- on karaf check the logs to see that the detector is running