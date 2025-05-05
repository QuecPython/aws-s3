# QuecPython AWS S3 Client

## Project Description
This project provides a lightweight AWS S3 client implementation that enables uploading, downloading, and deleting files (objects) in an S3 bucket.

The bucket must be pre-configured through the AWS Management Console, and this solution is intended for use with general-purpose S3 buckets.

It is designed for integration in embedded or constrained environments where direct interaction with S3 REST APIs is required, and supports AWS Signature Version 4 (SigV4) authentication for secure communication.

##  How to Install and Run the Project
To get started with this project, you should first clone the Repository:

Clone the project to your local machine using:

```bash
git clone https://github.com/QuecPython/aws-s3.git
```
Then set up the QuecPython development environment.
Follow the official QuecPython Getting Started Guide to set up all necessary tools:
https://python.quectel.com/doc/Getting_started/en/index.html

This guide walks you through:

Installing the required drivers for Quectel modules

Downloading and installing the IDE (QPYcom or QPYcom-IDE)

Flashing the latest QuecPython firmware

Setting up the development environment and connecting your module via USB

After completing the steps, you will be ready to run the example code and test MQTT connectivity to Azure IoT Hub.

## How to Use the Project
 
To use this AWS S3 client, follow these basic steps:

1. Create an AWS Account
If you don't already have one, sign up at aws.amazon.com.

2. Create an S3 Bucket
Use the AWS Management Console to create a general-purpose S3 bucket where you will upload, download, or delete files.

3. Configure and Run the Client
Once your bucket is set up, you can use this client to interact with it programmatically.

For detailed setup instructions, including how to configure credentials and initialize the client, refer to the [User Guide](./doc/user_guide.md).

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

In this example, the region, access key, secret key, bucket name, and download path are passed directly when creating the S3Client object. However, it is recommended to store these values in a config.json file located in the config/ directory for better separation of configuration and code.

## License 
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.