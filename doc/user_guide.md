# User Guide for Amazon S3  

## 1. Introduction  

### What is Amazon S3?  
Amazon S3 (Simple Storage Service) is a scalable, high-speed, web-based cloud storage service designed for online backup and archiving of data and applications. It provides developers and IT teams with secure, durable, and highly available object storage.  

### Purpose of this Guide  
This guide is designed to help users understand the basics of Amazon S3, including how to set up and use it effectively. By following this guide, you will learn how to create an S3 bucket, manage access, and work with files in S3.  

## 2. Preparation Before Using S3  

### 2.1. Creating an IAM User  

#### Why Use an IAM User Instead of the Root Account?  
Using an IAM user instead of the root account enhances security by limiting access and permissions to only what is necessary for specific tasks.  

#### Step-by-Step Guide to Creating an IAM User  
1. Log in to the AWS Management Console.  
2. Navigate to the **IAM** service.  
3. Click on **Users** and then **Create User**.  
4. Enter a username.  
5. Attach a policy (directly) (e.g., AmazonS3FullAccess) or create a custom policy.  
6. Review and create the user.  

### 2.2. Creating Access Key and Secret Access Key  

#### What Are Access Key and Secret Key?  
Access keys are credentials that allow programmatic access to AWS services. They consist of an access key ID and a secret access key.  

#### How to Generate and Store Them Securely  
1. After creating an IAM user, click on your IAM user name.
2. Go to **Security credentials**, then **Create access key**.
3. Select **Application running outside AWS** and create access key.
4. Download access key and secret access key.
4. Store them securely in a password manager, as environment variables or in config.json file.  
5. Avoid hardcoding them in your application.  

### 2.4. Creating an S3 Bucket  

#### Step-by-Step Guide to Creating a Bucket  
1. Navigate to the **S3** service in the AWS Management Console.  
2. Click **Create bucket**.  
3. Enter a unique bucket name.   
4. Versioning is not supported yet, so disable it.  
5. Leave default values, review and create the bucket.  

#### Note on Bucket Naming Rules  
Bucket names must be globally unique, between 3 and 63 characters, and cannot contain uppercase letters or underscores.  

### 2.5. Additional Details About S3 Buckets  
For more information about the S3 consistency model, versioning, and encryption options, see the official AWS documentation [here](https://docs.aws.amazon.com/s3/).  

## 3. Working with Files (Objects) in S3  

### 3.1. Uploading a File  

#### Short Explanation  
Uploading a file to S3 involves specifying the file path, object key which is a path to the object in the bucket and content type(text file, image etc. ).  

#### Code Example  
```python  
# Upload a file
s3_client.upload_file(filepath='usr/hello.txt', object_key='test-folder/hello.txt',content_type='text/str')
```  
### 3.2. Downloading a File  

#### Code Example  
```python  
# Download a file
s3_client.download_to_file(object_key='test-folder/hello.txt')  
```  

### 3.3. Deleting a File  

#### Code Example  
```python  
# Delete a file
s3_client.delete_file(object_key='test-folder/hello.txt') 
```  

## 4. Practical Example  

### Script Overview  
This script will:  
1. Upload a file to S3.  
2. Download the same file.  
3. Delete the file.

Before running the script, you need to add configuration details to the config.json file, such as the bucket name, access key, secret key, AWS region, and the download path (the local directory where downloaded files will be saved).

Alternatively, you can provide these configuration details directly through the S3 client constructor, but using a config file is recommended.

### Code Example  
```python 
from s3client import S3Client

s3_client = S3Client(
    region="eu-west-3",
    access_key="YOUR_ACCESS_KEY",
    secret_key="YOUR_SECRET_KEY",
    bucket="your-bucket-name",
    download_path="s3_downloads/"
)

# Upload a file
s3_client.upload_file(filepath='usr/hello.txt', object_key='test-folder/hello.txt',content_type='text/str')

# Download a file
s3_client.download_to_file(object_key='test-folder/hello.txt')

# Delete a file
s3_client.delete_file(object_key='test-folder/hello.txt')
```

### Instructions  
1. Replace `bucket` with your S3 bucket name.  
2. Replace `access_key` and `secret_key` with your access and secret key.  
3. Ensure your AWS credentials are configured properly.  
