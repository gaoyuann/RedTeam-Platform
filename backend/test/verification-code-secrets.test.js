import test from 'node:test';
import assert from 'node:assert/strict';
import {hasHardcodedCodeCredentials} from '../src/services/verificationCodeSecrets.js';

test('Cookie parsing, input variables and synthetic local samples are code, not credentials',()=>{
  const examples=[
    'cookie = SimpleCookie()', 'cookie = {}', 'cookie = response.headers.get("Set-Cookie")',
    'if cookie == "PHPSESSID":\n    print("cookie name")',
    'password = input("Password: ")', 'api_key = os.environ.get("API_KEY")',
    'headers["Cookie"] = cookie.output(header="").strip()',
    'headers["Authorization"] = "Bearer " + access_token',
    'headers["Authorization"] = f"Bearer {access_token}"',
    'cookie = "PHPSESSID=<SESSION_TOKEN>; Path=/; Secure; HttpOnly"',
    'headers = {"Cookie": "PHPSESSID=demo-session"}',
    'sample = "Set-Cookie: PHPSESSID=test-value; SameSite=Lax; Secure"',
    'cookie = "PHPSESSID"', 'password = ""',
    'cookie["PHPSESSID"] = "<SESSION_TOKEN>"', 'cookie["PHPSESSID"] = "demo-session"',
    'cookie["secure"] = "true"', 'cookie["PHPSESSID"]["samesite"] = "Lax"',
    'body = "password=<PASSWORD>"',
    'std::string cookie = parse_cookie(input);',
  ];
  for(const [index,source] of examples.entries())assert.equal(hasHardcodedCodeCredentials(source),false,'valid code example '+index);
});

test('literal credentials, session values and private keys remain blocked in Python, C and headers',()=>{
  const examples=[
    'password="fixture-secret"', 'const char *password = "fixture-secret";',
    'api_key = "fixture-sensitive-key"', 'access_token = "fixture-sensitive-token"',
    'client_secret = "fixture-sensitive-secret"',
    'headers = {"Authorization": "Bearer fixture-sensitive-token"}',
    'cookie = "PHPSESSID=fixture-sensitive-session; Path=/; HttpOnly"',
    'headers["Cookie"] = "PHPSESSID=fixture-sensitive-session"',
    'cookie["PHPSESSID"] = "fixture-sensitive-session"',
    'body = "password=fixture-sensitive-password&name=fixture"',
    'request = "Cookie: PHPSESSID=fixture-sensitive-session\\r\\n"',
    'cookie = "PHPSESSID=demo-session; other=fixture-sensitive-session"',
    'password = """fixture-sensitive-password"""',
    'key = "-----BEGIN PRIVATE KEY-----\\nfixture-only\\n-----END PRIVATE KEY-----"',
  ];
  for(const [index,source] of examples.entries())assert.equal(hasHardcodedCodeCredentials(source),true,'sensitive code example '+index);
});
