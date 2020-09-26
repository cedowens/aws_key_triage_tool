# AWS Key Triage (AKT) Script
This is a python script that leverages the boto3 library to automate initial triage/enumeration on a set (or multiple sets) of aws keys in an input file.

The goal of this tool is to speed up and automate the manual steps of running aws cli commands to determine whether aws keys in question are valid and if so what those keys have access to.

The script does the following checks:

- Checks if the keys are active

- Checks if the keys can view any secrets in the secretsmanager or parameter store

- Gets the user identity of the keys

- Attempts to list IAM users 

- Attempts to list services specific credential info

- Attemps to list the AWS account password policy

- Attempts to list IAM group info

- Attemps to describe ec2 instance info

- Attempts to list buckets and the top level directory/file within each bucket

- Attemps to list IAM role info

**Steps**
1. clone https://github.com/boto/boto3

2. cd into boto3 and run **sudo python3 setup.py install**. This will install boto3 and botocore.

3. put all of the aws key info in an input file that the script will read from. You will need the access key, secret key, and region for each key pair. Add these into a simple text file with each each row containing aws key, secret key, and region info separated by a comma in the following format for each row:

***accessky,secretky,region***

**I have included a sample input file (named sample_input_file.txt) showing the format to add your access keys, secret keys, and region info for each key pair you want to check**

4. **python3 akt.py -f [path_to_input_file]** - the script will perform triage checks on each key pair in this input file

5. I did not build outfile capability into this script...so to write results to a file: **python3 akt.py -f [path_to_input_file] > outfile.txt**
