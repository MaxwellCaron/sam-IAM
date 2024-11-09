# sam-IAM

Python brute force and enumeration script to determine what IAM permissions a specific AWS user has.

<br>

<div align="center">
  <img src="https://github.com/user-attachments/assets/d4b8dc62-b78f-4279-8b83-063eefe7ba63"/>
</div>

```
usage: main.py [-h] [--access-key ACCESS_KEY] [--secret-key SECRET_KEY] [--session-token SESSION_TOKEN] [--profile PROFILE] [--region REGION] [--no-border]

options:
  -h, --help            show this help message and exit
  --access-key ACCESS_KEY
                        Access key for the API. If provided, secret key is also required.
  --secret-key SECRET_KEY
                        Secret key for the API.
  --session-token SESSION_TOKEN
                        Token for the API session.
  --profile PROFILE     AWS profile to use in requests.
  --region REGION       AWS region to inspect.
  --no-border           Removes pretty bordering for easy copy and paste.
```

<br>

## Example

```
                                               
                                                 ╔══════╗                                                 
═════════════════════════════════════════════════╣ User ╠═════════════════════════════════════════════════
                                                 ╚══════╝                                                 
                                               
╔══════════╣ Attached
║                                                                                              
║ [+] Found 1 Attached Policy                                                                  
║      
║  
╠═════╣ [1] PublicSnapper (arn:aws:iam::104506445608:policy/PublicSnapper)
║                      
╠══╣ Get-Policy         
║ {              
║     "PolicyName": "PublicSnapper",
║     "PolicyId": "ANPARQVIRZ4UD6B2PNSLD",
║     "Arn": "arn:aws:iam::104506445608:policy/PublicSnapper",
║     "Path": "/",   
║     "DefaultVersionId": "v9",
║     "AttachmentCount": 1,
║     "PermissionsBoundaryUsageCount": 0,
║     "IsAttachable": true,
║     "CreateDate": "2023-06-10 22:33:41+00:00",
║     "UpdateDate": "2024-01-15 23:47:11+00:00",                                      
║     "Tags": []                                                                     
║ }                                                                                  
║             
╠══╣ Get-Policy-Version
║ {                                                                  
║     "Sid": "Intern1",                                               
║     "Effect": "Allow",                                               
║     "Action": "ec2:DescribeSnapshotAttribute",
║     "Resource": "arn:aws:ec2:us-east-1::snapshot/snap-0c0679098c7a4e636"
║ }                                                                       
║ {                                                                       
║     "Sid": "Intern2",                                                   
║     "Effect": "Allow",
║     "Action": "ec2:DescribeSnapshots",                                                       
║     "Resource": "*"
║ }
║ {
║     "Sid": "Intern3",
║     "Effect": "Allow",
║     "Action": [
║         "iam:GetPolicyVersion",
║         "iam:GetPolicy",
║         "iam:ListAttachedUserPolicies"
║     ],
║     "Resource": [
║         "arn:aws:iam::104506445608:user/intern",
║         "arn:aws:iam::104506445608:policy/PublicSnapper"
║     ]
║ }
║ {
║     "Sid": "Intern4",
║     "Effect": "Allow",
║     "Action": [
║         "ebs:ListSnapshotBlocks",
║         "ebs:GetSnapshotBlock"
║     ],
║     "Resource": "*"
║ }

╔══════════╣ Inline
 Access Denied

                                      ╔════════════════════════════╗                                      
══════════════════════════════════════╣ "intern" Group Memberships ╠══════════════════════════════════════
                                      ╚════════════════════════════╝                                      
 Access Denied

                                             ╔══════════════╗                                             
═════════════════════════════════════════════╣ Other Groups ╠═════════════════════════════════════════════
                                             ╚══════════════╝                                             
 Access Denied

                                                ╔═══════╗                                                 
════════════════════════════════════════════════╣ Roles ╠═════════════════════════════════════════════════
                                                ╚═══════╝                                                 
 Access Denied
```
