import boto3
from botocore.exceptions import ClientError
import json

s3_client = boto3.client('s3')

def create_bucket(bucket_name):
    try:
        response = s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': 'eu-west-1'
            }
        )
        print(f"Bucket {bucket_name} created successfully.")
        return response
    except ClientError as e:
        print(f"Error creating bucket: {e}")
        return None
    
def set_bucket_policy(bucket_name):
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }
    bucket_policy_json = json.dumps(bucket_policy)
    
    try:
        response = s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=bucket_policy_json
        )
        print(f"Bucket policy set for {bucket_name}.")
        return response
    except ClientError as e:
        print(f"Error setting bucket policy: {e}")
        return None
    
def enable_bucket_encryption(bucket_name):
    encryption_configuration = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            },
        ]
    }
    
    try:
        response = s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_configuration
        )
        print(f"Encryption enabled for {bucket_name}.")
        return response
    except ClientError as e:
        print(f"Error enabling encryption: {e}")
        return None
    

def set_lifecycle_policy(bucket_name):
    lifecycle_policy = {
        'Rules': [
            {
                'ID': 'Delete old files',
                'Prefix': '',
                'Status': 'Enabled',
                'Expiration': {
                    'Days': 30
                }
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_policy
        )
        print(f"Lifecycle policy set for {bucket_name}.")
        return response
    except ClientError as e:
        print(f"Error setting lifecycle policy: {e}")
        return None


def upload_file(bucket_name, file_name, object_name=None):
    if object_name is None:
        object_name = file_name
    
    try:
        response = s3_client.upload_file(file_name, bucket_name, object_name)
        print(f"File {file_name} uploaded to {bucket_name}/{object_name}.")
        return response
    except ClientError as e:
        print(f"Error uploading file: {e}")
        return None
    
def delete_objects(bucket_name):
    try:
        objects = s3_client.list_objects_v2(Bucket=bucket_name).get('Contents', [])
        for obj in objects:
            s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
            print(f"Deleted {obj['Key']} from {bucket_name}.")
    except ClientError as e:
        print(f"Error deleting objects: {e}")


def delete_bucket(bucket_name):
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting bucket: {e}")


bucket_name = 'pandiyanbucket' 

create_bucket(bucket_name)

set_bucket_policy(bucket_name)

enable_bucket_encryption(bucket_name)

set_lifecycle_policy(bucket_name)

files_to_upload = [ 'error.html']
for file_name in files_to_upload:
    upload_file(bucket_name, file_name)


delete_objects(bucket_name)

delete_bucket(bucket_name)