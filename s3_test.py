from usr import s3client

s3_client = s3client.S3Client()
a = s3_client.download_to_file('')

data = ''
b = s3_client.upload_file(data, object_key="", content_type="")
