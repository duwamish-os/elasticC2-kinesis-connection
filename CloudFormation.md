
create access-role stack
--

delete stack
---

```bash
aws cloudformation delete-stack --stack-name streaming-access --region us-west-2 --profile creds-federated
```

```bash
aws cloudformation create-stack --stack-name streaming-access-role --template-body file://StreamingAccessRoleCF.json --profile creds-federated --region us-west-2 --capabilities CAPABILITY_IAM
{
    "StackId": "arn:aws:cloudformation:us-west-2:033814027302:stack/streaming-access-role/4c2718b0-1a61-11e7-903b-503ac931688d"
}
```

describe access-role stack
--

```bash
aws cloudformation describe-stacks --stack-name streaming-access-role --region us-west-2 --profile aws-federated
{
    "Stacks": [
        {
            "StackId": "arn:aws:cloudformation:us-west-2:033814027302:stack/streaming-access-role/b2c41660-1a5f-11e7-80b3-50d5ca11b8d2", 
            "Tags": [], 
            "CreationTime": "2017-04-06T00:26:57.902Z", 
            "Capabilities": [
                "CAPABILITY_IAM"
            ], 
            "StackName": "streaming-access-role", 
            "NotificationARNs": [], 
            "StackStatus": "ROLLBACK_COMPLETE", 
            "DisableRollback": false
        }
    ]
}
```

```
aws iam list-roles --region us-west-2 --profile aws-federated | grep streaming
```

create instance stack
---

```bash
aws cloudformation create-stack --stack-name streaming-server --template-body file://StreamingCloudInstance.json --profile aws-federated --region us-west-2
```

![cloud_formation_instance.png](cloud_formation_instance.png)

http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html

[Amazon EC2 Template Snippets](http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-ec2.html)
