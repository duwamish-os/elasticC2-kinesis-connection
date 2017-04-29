
[LB](https://www.rackspace.com/en-us/cloud/load-balancing)
-----

```
With an "A" Load Balancer, the LB node that receives the request evaluates the listener rules in priority order 
to determine which rule to apply, and then selects a target from the target group for 
the rule action using the round robin routing algorithm.
```

```json

aws elb describe-load-balancers --load-balancer-name orders-Ingestio-1JWKPA8NIWNCW --region us-west-2 --profile aws-federated
{
    "LoadBalancerDescriptions": [
        {
            "Subnets": [
                "subnet-d67baeb3"
            ], 
            "CanonicalHostedZoneNameID": "Z1H1FL5HABSF5",
            "VPCId": "vpc-6207ff07",
            "ListenerDescriptions": [
                {
                    "Listener": {
                        "InstancePort": 80, 
                        "LoadBalancerPort": 80, 
                        "Protocol": "HTTP", 
                        "InstanceProtocol": "HTTP"
                    }, 
                    "PolicyNames": []
                }
            ], 
            "HealthCheck": {
                "HealthyThreshold": 3, 
                "Interval": 30, 
                "Target": "HTTP:80/", 
                "Timeout": 5, 
                "UnhealthyThreshold": 5
            }, 
            "BackendServerDescriptions": [], 
            "Instances": [
                {
                    "InstanceId": "i-0b17f438174c4d254"
                }
            ], 
            "DNSName": "internal-orders-Ingestio-1JWKPA8NIWNCW-1550025936.us-west-2.elb.amazonaws.com", 
            "SecurityGroups": [
                "sg-285ee853"
            ], 
            "Policies": {
                "LBCookieStickinessPolicies": [], 
                "AppCookieStickinessPolicies": [], 
                "OtherPolicies": []
            }, 
            "LoadBalancerName": "orders-Ingestio-1JWKPA8NIWNCW", 
            "CreatedTime": "2017-04-21T06:48:19.510Z", 
            "AvailabilityZones": [
                "us-west-2a"
            ], 
            "Scheme": "internal",
            "SourceSecurityGroup": {
                "OwnerAlias": "500238854089", 
                "GroupName": "orders-endpoint-uat-IngestionApiFirewall-EPP9UAN6NHKY"
            }
        }
    ]
}

```

Ref
----

[How Load Balancing Works/ Routing Algorithm](http://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/how-elastic-load-balancing-works.html)

https://aws.amazon.com/articles/1636185810492479

https://www.rackspace.com/en-us/cloud/load-balancing

http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html

https://aws.amazon.com/blogs/devops/passing-parameters-to-cloudformation-stacks-with-the-aws-cli-and-powershell/
