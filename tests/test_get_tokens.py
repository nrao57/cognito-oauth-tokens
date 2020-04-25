from tokens.utils import encode_secrets, create_payload, create_headers, post_request, decode_tokens
import unittest
import json


class TestTokenMethods(unittest.TestCase):
    def setUp(self):
        self.redirect_uri = 'REDIRECT_URI'
        self.url = 'COGNITO_TOKENS_ENDPOINT'
        self.client_id = 'CLIENT_ID'
        self.client_secret = 'CLIENT_SECRET'

    def test_codesecrets(self):
        result = encode_secrets(self.client_id, self.client_secret)
        self.assertEqual(result, 'Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=')

    def test_createpayload(self):
        authorization_code = 'test_code'
        result = create_payload(self.client_id, self.redirect_uri, authorization_code)
        self.assertEqual(result, {'grant_type': 'authorization_code', 'client_id': 'CLIENT_ID', 'scope': 'profile', 'redirect_uri': 'REDIRECT_URI', 'code': 'test_code'})

    def test_createheaders(self):
        result = create_headers(self.client_id, self.client_secret)
        self.assertEqual(result, {'content-type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ='})

    def test_decodetokens(self):
        data = 'eyJraWQiOiJrMlNwM0g3N1FnNnhsaVZGVXpaaFJOYklsQTZWcGxQcGZkXC8xeUhzVEJlST0iLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiYUhtT09LYjYtMmlWZ1IwY2c1Yl9OdyIsInN1YiI6IjFiYTFiZWUyLTkzMGEtNDViYi05ZmE0LTUwNTc1YTlkMDc5OCIsImF1ZCI6IjVxNzg1bjY3bXUxc2Q4YmJqdXFqMnBja2o3IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTg3NTk2NTIyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9CN01xSXFFeHAiLCJjb2duaXRvOnVzZXJuYW1lIjoidGVzdDEyMzQiLCJleHAiOjE1ODc2MDAxMjIsImlhdCI6MTU4NzU5NjUyMiwiZW1haWwiOiJhaWdnbWJkbHFhcHp0bWRjeGFAYXdkcnQubmV0In0.gbgrx7aqdzvxX8iR9q6LD5o9tu1uIIFeJT9mYpYAzUvOfc6EQ-9GAFflPLvv8gNSk6jaVBM5aUbQ_Dpp8R5sGDx-6_Um4zgEHUxJiNe3gjEpc-vcVbZwr2_qlH8-9n1ZvCcIHI3Wd4xKUUeKZWJpJKww1-iF8DiXo6KBErvINoiankB_XtpuC_1Sg3LW-_vnTcHpY8NVYWwmWP6st5Eq0W2ecLCKZ8FRzVe7L7jzCm2nP_EYgw-1DasqqkfmUkUv1w4kSQ3i00KKST3R60rXcQJdwBUo4tIdALH0hi4eGZDwY2wQ3Fh2fKNS7BfmHsvwAP9ftKEhN_34NHM-NfjOLQ'
        result = decode_tokens(data)
        self.assertEqual(result, {'at_hash': 'aHmOOKb6-2iVgR0cg5b_Nw', 'sub': '1ba1bee2-930a-45bb-9fa4-50575a9d0798', 'aud': '5q785n67mu1sd8bbjuqj2pckj7', 'email_verified': True, 'token_use': 'id', 'auth_time': 1587596522, 'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B7MqIqExp', 'cognito:username': 'test1234', 'exp': 1587600122, 'iat': 1587596522, 'email': 'aiggmbdlqapztmdcxa@awdrt.net'})

if __name__ == '__main__':
    unittest.main()