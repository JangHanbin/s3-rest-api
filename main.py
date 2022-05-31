from Auth import Auth
import sys
import requests

if __name__ == '__main__':
    access_key = ''
    secret_key = ''
    method = 'GET'
    service = 's3'
    region = 'ap-northeast-2'

    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    url = 'https://{0}-{1}.amazonaws.com/'.format(service, region)
    auth = Auth(access_key, secret_key, method, service, region, url, '')

    headers = auth.make_headers()

    r = requests.get(url, headers=headers)
    print(r.request.headers)
    print(r.status_code)
    print(r.text)