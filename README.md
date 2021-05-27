# AWS Key Triage (AKT) Script
Python scripts that leverage the boto3 library to automate initial triage/enumeration on a set (or multiple sets) of aws keys in an input file.

I have included two scripts:

- one for triage of aws creds found on endpoints (which usually do not have an access token)
- one for triage of aws creds found on servers or via metadata service queries (which do usually have an access token)

The goal of this tool is to speed up and automate the manual steps of running aws cli commands to determine whether aws keys in question are valid and if so what those keys have access to.

The script does the following checks:

- Checks if the keys are active

- Checks if the keys can view any secrets in the secretsmanager or parameter store

- Gets the user identity of the keys

- Attempts to list IAM users 

- Attempts to list services specific credential info

- Attempts to list the AWS account password policy

- Attempts to list IAM group info

- Attempts to describe ec2 instance info

- Attempts to list buckets and the top level directory/file within each bucket

- Attempts to list IAM role info

- Attempts to list lambda functions

**Steps**
1. clone https://github.com/boto/boto3

2. cd into boto3 and run **sudo python3 setup.py install**. This will install boto3 and botocore.

3. put all of the aws key info in an input file that the script will read from. **If using aws keys that do not have an access token, then use the akt.py script and set up your input file in the format of sample_input_file.txt. If you are using aws keys that do have an access token, use the akt-token.py script and set your input file in the format of sample-input-file-token.txt.** Add the aws cred information accordingly in a simple .txt file matching either option.

For uses of keys that do not have an access token:

***accessky,secretky,region***

For uses of keys that do have an access token:

***accessky,secretky,region,accesstoken

**I have included a sample input files (sample_input_file.txt and sample-input-file-token.txt) showing the format to add your aws cred info depending on whether or not it uses an access token**

4. **python3 akt.py -f [path_to_input_file]** OR **python3 akt-token.py -f [path_to_input_file]**

5. Results will be written to stdout
