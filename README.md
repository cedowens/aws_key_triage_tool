# AWS Key Triage (AKT) Script
This is a python script that leverages the boto3 library to automate initial triage/enumeration on a set (or multiple sets) of aws keys in an input file.

The goal of this tool is to speed up and automate the manual steps of running aws cli commands to determine whether aws keys in question are valid and if so what those keys have access to.

The script does the following checks:

- Checks if the keys are active

- Checks if the keys can view any secrets in the secretsmanager or parameter store

- Gets the user identity of the keys

- Attempts to lists IAM users 

- Attempts to list services specific credential info

- Attemps to list the AWS account password policy

- Attempts to list IAM group info

- Attemps to describe ec2 instance info

- Attempts to list buckets and the top level directory/file within each bucket

- Attemps to list IAM role info

**Steps**
1. pip3 install -r requirements.txt (will install boto3)

2. put all of the aws key info in an input file that the script will read from. This should be a simple text file with each each row containing aws key info separated by a comma in the following format:

***accessky,secretky,region***

**example file content:**

sampleaccesskey,samplesecretkey,us-west-1

sampleaccesskey2,samplesecretkey2,us-east-2

sampleaccesskey3,samplescretkey3,us-west-2

.

.

.

3. **python3 aws_key_triage_tool.py -f [path_to_input_file]** - the script will perform triage checks on each key pair in this input file

4. I did not build outfile capability into this script...so to write results to a file: **python3 aws_key_triage_tool.py -f [path_to_input_file] > outfile.txt**
