import request
import utime
import ubinascii
import uhashlib
import ujson
import uos

class S3Client:
    def __init__(self, region=None, access_key=None, secret_key=None, bucket=None, config_path="usr/config.json", download_path=None):
        if not all([region, access_key, secret_key, bucket]):
            cfg = self._load_config(config_path)
            self.region = region or cfg.get("region")
            self.access_key = access_key or cfg.get("access_key")
            self.secret_key = secret_key or cfg.get("secret_key")
            self.bucket = bucket or cfg.get("bucket")
            self.download_path = download_path or cfg.get('download_path')
        else:
            self.region = region
            self.access_key = access_key
            self.secret_key = secret_key
            self.bucket = bucket
        self.service = "s3"

    def _load_config(self, path):
        try:
            with open(path, "r") as f:
                return ujson.load(f)
        except Exception as e:
            print(e)

    def _hmac_sha256(self, key, msg):
        blocksize = 64  # za SHA-256

        if len(key) > blocksize:
            key = uhashlib.sha256(key).digest()
        if len(key) < blocksize:
            key += b'\x00' * (blocksize - len(key))

        o_key_pad = bytes([b ^ 0x5C for b in key])
        i_key_pad = bytes([b ^ 0x36 for b in key])

        inner = uhashlib.sha256(i_key_pad + msg).digest()
        outer = uhashlib.sha256(o_key_pad + inner).digest()

        return outer

    def _get_signature_key(self, date_stamp):
        kDate = self._hmac_sha256(('AWS4' + self.secret_key).encode(), date_stamp.encode())
        kRegion = self._hmac_sha256(kDate, self.region.encode())
        kService = self._hmac_sha256(kRegion, self.service.encode())
        kSigning = self._hmac_sha256(kService, b'aws4_request')
        return kSigning

    def _get_amz_dates(self):
        mk_t = utime.localtime()
        mk = utime.mktime(mk_t) - 2*3600
       
        t = utime.localtime(mk)
        amz_date = "{:04d}{:02d}{:02d}T{:02d}{:02d}{:02d}Z".format(t[0], t[1], t[2], t[3], t[4], t[5])
        date_stamp = "{:04d}{:02d}{:02d}".format(t[0], t[1], t[2])

        print(amz_date)

        return amz_date, date_stamp

    def _get_object(self, object_key):
        
        amz_date, date_stamp = self._get_amz_dates()

        method = "GET"
        canonical_uri = "/{}".format(object_key)
        canonical_querystring = ""
        host = "{}.s3.{}.amazonaws.com".format(self.bucket, self.region)
        
        payload_hash = ubinascii.hexlify(uhashlib.sha256(b'').digest()).decode()

        canonical_headers = (
            "host:{}\n"
            "x-amz-content-sha256:{}\n"
            "x-amz-date:{}\n"
        ).format(host, payload_hash, amz_date)

        signed_headers = "host;x-amz-content-sha256;x-amz-date"

        canonical_request = "\n".join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        ])

        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, self.region, self.service)
        string_to_sign = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            ubinascii.hexlify(uhashlib.sha256(canonical_request.encode()).digest()).decode()
        ])

        signing_key = self._get_signature_key(date_stamp)
        signature = ubinascii.hexlify(self._hmac_sha256(signing_key, string_to_sign.encode())).decode()

        authorization_header = (
            "{} Credential={}/{}, SignedHeaders={}, Signature={}"
            .format(algorithm, self.access_key, credential_scope, signed_headers, signature)
        )

        headers = {
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization_header
        }

        url = "https://{}/{}".format(host, object_key)
        response = request.get(url=url, headers=headers, decode=True)
        return response
    
    def _put_object(self, object_key, data, content_type='application/octet-stream'):
        amz_date, date_stamp = self._get_amz_dates()

        method = "PUT"
        canonical_uri = "/{}".format(object_key)
        canonical_querystring = ""
        host = "{}.s3.{}.amazonaws.com".format(self.bucket, self.region)

        payload_hash = ubinascii.hexlify(uhashlib.sha256(data).digest()).decode()

        canonical_headers = (
            "content-type:{}\n"
            "host:{}\n"
            "x-amz-content-sha256:{}\n"
            "x-amz-date:{}\n"
        ).format(content_type, host, payload_hash, amz_date)

        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"

        canonical_request = "\n".join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        ])

        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, self.region, self.service)
        string_to_sign = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            ubinascii.hexlify(uhashlib.sha256(canonical_request.encode()).digest()).decode()
        ])

        signing_key = self._get_signature_key(date_stamp)
        signature = ubinascii.hexlify(self._hmac_sha256(signing_key, string_to_sign.encode())).decode()

        authorization_header = (
            "{} Credential={}/{}, SignedHeaders={}, Signature={}"
            .format(algorithm, self.access_key, credential_scope, signed_headers, signature)
        )

        headers = {
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization_header,
            "content-type": content_type
        }

        url = "https://{}/{}".format(host, object_key)
        response = request.put(url=url, headers=headers, data=data, decode=True)
        return response
    
    
    def _delete_object(self, object_key):
        try:
            amz_date, date_stamp = self._get_amz_dates()
            method = "DELETE"
            canonical_uri = "/{}".format(object_key)
            canonical_querystring = ""
            host = "{}.s3.{}.amazonaws.com".format(self.bucket, self.region)
            payload_hash = ubinascii.hexlify(uhashlib.sha256(b'').digest()).decode()

            canonical_headers = (
                "host:{}\n"
                "x-amz-content-sha256:{}\n"
                "x-amz-date:{}\n"
            ).format(host, payload_hash, amz_date)

            signed_headers = "host;x-amz-content-sha256;x-amz-date"
            canonical_request = "\n".join([
                method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash
            ])

            algorithm = "AWS4-HMAC-SHA256"
            credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, self.region, self.service)
            string_to_sign = "\n".join([
                algorithm,
                amz_date,
                credential_scope,
                ubinascii.hexlify(uhashlib.sha256(canonical_request.encode()).digest()).decode()
            ])

            signing_key = self._get_signature_key(date_stamp)
            signature = ubinascii.hexlify(self._hmac_sha256(signing_key, string_to_sign.encode())).decode()

            authorization_header = (
                "{} Credential={}/{}, SignedHeaders={}, Signature={}"
                .format(algorithm, self.access_key, credential_scope, signed_headers, signature)
            )

            headers = {
                "x-amz-date": amz_date,
                "x-amz-content-sha256": payload_hash,
                "Authorization": authorization_header
            }

            url = "https://{}/{}".format(host, object_key)
            response = request.delete(url=url, headers=headers, decode=True)
            return response
        except Exception as e:
            print("Exception during DELETE:", e)
            return None

    def upload_file(self, filepath, object_key, content_type='application/octet-stream'):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            response = self._put_object(object_key, data, content_type)
            return response
        except Exception as e:
            print("Exception during upload:", e)
            return None

    def download_to_file(self, object_key):
        try:
            response = self._get_object(object_key)
            filename = object_key.split('/')[-1]
            self.new_path = self.download_path + filename

            if response.status_code == 200:
                with open(self.new_path, "wb") as f:
                    content = response.content
                    for i in content:
                        f.write(i)
            else:
                print("Download failed with status:", response.status_code)
            return response
        except OSError as e:
            if e.args[0] == 19:
                print("Download path doesn't exist.")
            else: 
                print("Exception during download:", e)
            return None
        except Exception as e:
            print("Exception during download:", e)
            return None
       

    def delete_file(self, object_key):
        try:
            response = self._delete_object(object_key)
            if response.status_code == 204:
                print("File deleted successfully.")
            else:
                print("Removal failed with status", response.status_code)
            return response
        except Exception as e:
            print("Exception during delete file.", e)
            return None