import datetime, hashlib, hmac
import urllib.parse

class Auth:
    def __init__(self, access_key, secret_key, method, service, region, url, payload):
        self.access_key = access_key
        self.secret_key = secret_key
        self.method = method
        self.service = service
        self.region = region
        self.host = '{0}-{1}.amazonaws.com'.format(service, region)
        self.url = urllib.parse.urlparse(url)
        self.canonical_uri = '/' if not self.url.path else self.url.path
        self.canonical_querystring = self.url.query
        self.utc = datetime.datetime.utcnow()
        self.signed_headers = 'host;x-amz-content-sha256;x-amz-date'
        self.amzdate = self.utc.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = self.utc.strftime('%Y%m%d')
        self.payload_hash = hashlib.sha256((payload).encode('utf-8')).hexdigest()
        self.signing_key = self.get_signature_key(self.secret_key)
        self.canonical_header = self.make_canonical_header()
        self.canonical_request = self.make_canonical_request()

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, key):
        k_date = self.sign(('AWS4' + key).encode('utf-8'), self.datestamp)
        k_region = self.sign(k_date, self.region)
        k_service = self.sign(k_region, self.service)
        k_signing = self.sign(k_service, 'aws4_request')
        return k_signing

    def make_canonical_header(self):
        return 'host:{0}\nx-amz-content-sha256:{1}\nx-amz-date:{2}\n'.format(self.host, self.payload_hash, self.amzdate)

    def make_canonical_request(self):
        return '{0}\n{1}\n{2}\n{3}\n{4}\n{5}'.format(self.method, self.canonical_uri, self.canonical_querystring, self.canonical_header, self.signed_headers, self.payload_hash)

    def make_headers(self):
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = '{0}/{1}/{2}/aws4_request'.format(self.datestamp, self.region, self.service)
        string_to_sign = '{0}\n{1}\n{2}\n{3}'.format(algorithm, self.amzdate, credential_scope, hashlib.sha256(
            self.canonical_request.encode('utf-8')).hexdigest())

        signature = hmac.new(self.signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        auth_header = '{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}'.format(algorithm, access_key, credential_scope, self.signed_headers, signature)
        headers = {'x-amz-date': self.amzdate, 'x-amz-content-sha256': self.payload_hash, 'Authorization': auth_header}
        return headers

