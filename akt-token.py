import boto3
import os
import sys
import optparse
from optparse import OptionParser

if (len(sys.argv) != 3 and '-h' not in sys.argv):
    print("Usage: python3 %s -f [path_to_input_file]\n" % sys.argv[0])
    sys.exit(0)

def banner():
    print("***********************************************")
    print("*                                             *")
    print("* AWS Key Triage Tool                         *")
    print("* @cedowens                                   *")
    print("***********************************************")
    print("")
    print("")
#################
def secretscheck(akey,skey,region,token):
    print("--------------> secretsmanager check:")
    client = boto3.client('secretsmanager',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    pag = client.get_paginator('list_secrets')
    iterator = pag.paginate()

    for page in iterator:
        secdict = page['SecretList']
        secdict2 = str(secdict).split(",")
        for each in secdict2:
            if "'ARN'" in each:
                print(each.replace("[","").replace("{",""))
            elif "'Name'" in each:
                print(each)
                secname = each.replace("'Name': ","").replace("'","").replace(" ","")
                try:
                    resp = client.get_secret_value(SecretId=secname)
                    print(str(resp['SecretString']).replace("{","").replace("}",""))
                except:
                    print("[-] Error attempting to get the SecretString for %s"%each)

            elif "'Description'" in each:
                print(each)
                print("")
            else:
                pass
    print("--------------> parameter store check:")
    paramlist = []
    client2 = boto3.client('ssm',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    pag2 = client2.get_paginator('describe_parameters')
    iterator2 = pag2.paginate()


    try:
        pag2 = client2.get_paginator('describe_parameters')
        iterator2 = pag2.paginate()

        for pg in iterator2:
            mydict = pg['Parameters']
            mydict2 = str(mydict).split(",")
            for item in mydict2:
                if "'Name'" in item:
                    name2 = item.replace("{'Name': ", "").replace("'","").replace("[","").replace("]","")
                    paramlist.append(name2)
            for name in paramlist:
                print("===> %s" % name)
                resp2 = client2.get_parameter(Name=name,WithDecryption=True)
                results = resp2['Parameter']
                print(results['Value'])
    except Exception:
        pass
##################
def whoami(akey,skey,region,token):
    print("--------------> get-caller-identity check:")
    client = boto3.client('sts',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.get_caller_identity()
        print("Account: %s"%str(response['Account']))
        print("UserId: %s"%str(response['UserId']))
        print("Arn: %s"%str(response['Arn']))

    except Exception:
        pass
##################
def listusers(akey,skey,region,token):
    print("--------------> attempting to list iam users:")
    client = boto3.client('iam',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.list_users()
        response2 = response['Users']
        resp3 = str(response2).split(',')

        for item in resp3:
            if 'UserName' in item:
                print("==>%s"%item)
            elif 'UserId' in item:
                print(item)
            elif 'Arn' in item:
                print(item)
                print('')
            else:
                pass

    except Exception:
        pass
###################
def sscreds(akey,skey,region,token):
    print("--------------> list servicespecificcredentials:")
    client = boto3.client('iam',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.list_service_specific_credentials()
        response2 = response['ServiceSpecificCredentials']
        response3 = str(response2).split(',')

        for item in response3:
            if 'UserName' in item and 'ServiceUserName' not in item:
                print("==>%s"%item)
            elif 'Status' in item:
                print(item)
            elif 'ServiceName' in item:
                print(item)
            elif 'ServiceSpecificCredentialId' in item:
                print(item)
            elif 'ServiceUserName' in item:
                print(item)

    except Exception:
        pass
#####################
def passpol(akey,skey,region,token):
    print("--------------> get AWS account password policy:")
    client = boto3.client('iam',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.get_account_password_policy()
        response2 = response['PasswordPolicy']
        print(response2)
    except Exception as e:
        pass
#####################
def listgroups(akey,skey,region,token):
    print("--------------> list IAM group info:")
    client = boto3.client('iam',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.list_groups()
        response2 = response['Groups']
        response3 = str(response2).split(',')
        for each in response3:
            if 'GroupName' in each:
                print("==>%s"%each)
            elif 'Arn' in each:
                print(each)
            elif 'GroupId' in each:
                print(each)

    except Exception:
        pass
#######################
def instanceinfo(akey,skey,region,token):
    print("--------------> Attempt to describe ec2 instances:")
    client = boto3.client('ec2',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.describe_instances()
        response2 = response['Reservations']
        response3 = str(response2).split(',')
        for each in response3:
            if 'PrivateIpAddress' in each and 'PrivateIpAddresses' not in each:
                print("==>%s"%each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'VpcId' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'InstanceId' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'PrivateDnsName' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'KeyName' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'GroupName' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'GroupId' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'ClientToken' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'MacAddress' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'Architecture' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            elif 'Value' in each:
                print(each.replace("}","").replace("]","").replace("{","").replace("[",""))
            else:
                pass

    except Exception:
        pass
#########################
def listbuckets(akey,skey,region,token):
    print("--------------> Attempt to list s3 buckets available to these AWS keys:")
    client = boto3.client('s3',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.list_buckets()
        response2 = response['Buckets']
        response3 = str(response2).split(',')
        bucklist = []

        for each in response3:
            if 'Name' in each:
                print("==>%s"%each.replace("{","").replace("}","").replace("[","").replace("]",""))
                each2 = each.replace("'","").replace("{","").replace("}","").replace("[","").replace("]","")
                bucklist.append(each2)
            elif 'DisplayName' in each:
                print(each.replace("{","").replace("}","").replace("[","").replace("]",""))
            elif 'ID' in each:
                print(each.replace("{","").replace("}","").replace("[","").replace("]",""))
        if len(bucklist) > 0:
            print("\n----attempting to list top level dir in each bucket found...\n")
            for name in bucklist:
                name2 = name.replace("[{Name: ","").replace("]","").replace("}","").replace("{","").replace("Name: ","").replace(" ","")
                try:
                    response4 = client.list_objects(Bucket=name2, Prefix='', Delimiter='/')
                    response5 = response4['Contents']
                    response6 = str(response5).split(',')
                    for x in response6:
                        if 'Key' in x:
                            print("===>Bucket name: " + name2)
                            print("Top Level Content: %s" % x.replace("{'Key': ","").replace("[","").replace("]",""))
                            print("")
                        else:
                            pass
                except:
                    pass

    except Exception:
        pass
##########################
def listroles(akey,skey,region,token):
    print("--------------> Attempt to list IAM roles:")
    client = boto3.client('iam',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
    try:
        response = client.list_roles()
        response2 = response['Roles']
        response3 = str(response2).split(',')

        for each in response3:
            if 'RoleName' in each:
                print("===>Role Name: %s" % each.replace("'RoleName': ","").replace("{","").replace("}","").replace("[","").replace("]",""))
            elif 'RoleId' in each:
                print("RoleId: %s" % each.replace("'RoleId': ","").replace("{","").replace("}","").replace("[","").replace("]",""))
            elif 'Arn' in each:
                print("Arn: %s\n" % each.replace("'Arn': ","").replace("{","").replace("}","").replace("[","").replace("]",""))
            else:
                pass

    except Exception:
        pass
###########################


parser = OptionParser()
parser.add_option("-f", "--file", help="Path to input file with AWS creds")
(options,args) = parser.parse_args()

file = options.file

if os.path.exists(file):
    banner()
    credslist = []

    with open(file,'r') as credfile:
        for line in credfile:
            parsed = line.strip().split(",")
            akey = parsed[0]
            skey = parsed[1]
            region = parsed[2]
            token = parsed[3]

            try:
                print("=======> Attempting %s:%s ..." % (akey,skey))
                client = boto3.client('sts',aws_access_key_id=akey,aws_secret_access_key=skey,aws_session_token=token,region_name=region)
                client.get_caller_identity()
                print("%s:::%s --> Creds are valid" % (akey,skey))
                print('')
                whoami(akey,skey,region,token)
                listusers(akey,skey,region,token)
                sscreds(akey,skey,region,token)
                passpol(akey,skey,region,token)
                listgroups(akey,skey,region,token)
                instanceinfo(akey,skey,region,token)
                listbuckets(akey,skey,region,token)
                listroles(akey,skey,region,token)
                secretscheck(akey,skey,region,token)
                print("*"*100)
            except Exception as e:
                pass
                print("Error with this key set: %s:%s" % (akey,skey))
                print("Error details:")
                print(e)
                print("*"*100)


    print("[+] DONE!")

else:
    print("[-] %s not found. Exiting..." % file)
