Contents -
* [Considerations](#-considerations)
* [Credentials](#-credential-operations)
 * [Get Credential by ID](#-get-a-credential-by-id)
 * [Finding Credentials](#-finding-credentials)
    * [Finding Credentials by Name](#-finding-credentials-by-partial-name)
    * [Finding Credentials by Path](#-finding-credentials-by-path)
 * [Delete Credential](#delete-a-credential)
 * [Type-Specific Operations](#-type-specific-operations)
    * [Password Credentials](#-password-credentials)
       * [Get Password](#get-a-password-credential)
       * [Set Password](#set-a-static-password-credential)
       * [Generate Password](#set-a-generated-password-credential)
    * [Certificate Credentials](#-certificate-credentials)
       * [Get Certificate](#get-a-certificate-credential)
       * [Set Certificate or CA](#set-a-static-certificate-or-ca-credential)
       * [Generate Certificate](#set-a-generated-certificate-credential)
       * [Generate a CA Certificate](#set-a-generated-ca-certificate-credential)
    * [SSH Credentials](#-ssh-credentials)
       * [Get SSH](#get-an-ssh-credential)
       * [Set SSH](#set-a-static-ssh-credential)
       * [Generate SSH](#set-a-generated-ssh-credential)
    * [RSA Credentials](#-rsa-credentials)
       * [Get RSA](#get-an-rsa-credential)
       * [Set RSA](#set-a-static-rsa-credential)
       * [Generate RSA](#set-a-generated-rsa-credential)
    * [Value Credentials](#-value-credentials)
       * [Get Value](#get-a-value-credential)
       * [Set Value](#set-a-static-value-credential)
    * [JSON Credentials](#-json-credentials)
       * [Get Value](#get-a-json-credential)
       * [Set Value](#set-a-static-json-credential)


---
## <a></a> Considerations

#### Credential Naming and Paths
Credentials can be named with any value containing ascii alpha and numeric characters. Special characters should not be used in credential paths or names, except dash (-) and underscore (_). 

Paths can be used to namespace a set of credential names for a different deployment or environment. To add a path to a credential, simply add the path prior to the credential name, separated by a forward slash (/), e.g. `credhub set -t password -n /prod/deploy123/cc_password -v 'value'`. If a leading slash is not provided, it will be automatically be appended. A credential's path and name must be less than 256 characters. 

#### Authorization
All CredHub endpoints, except /info and /health, are restricted to authorized users. API requests must contain an Authorization header with a bearer access token. To obtain an access token, you can either log in with user credentials or use a client_credentials grant from the authorized UAA. You can obtain the address of the authorized UAA for a given CredHub by sending a request to the /info endpoint. 

#### Credential ID
Credential responses include a unique identifier in the key 'id'. This ID is unique to the credential and value. If the value is modified a new ID will be returned. This is useful in applications where a specific credential value should be pinned until a manual action (such as a deployment) is performed.

#### Overwriting Credential Values
By default, credential set and generate actions with the API will not overwrite an existing value. If you wish to only create values that do not exist, you can perform generate requests on all of the credentials and it leave existing values in place. If you wish to overwrite existing values, you must include the `"overwrite": true` parameter in your request. Note - This parameter does not apply to CA updates, which will always be updated for a requested action.

## <a></a> Credential Operations

Credentials are the primary object in CredHub. Any passwords, secrets, configurations or other sensitive information that you store is saved to a named credential. You can retrieve, update and delete a credential using its name. All credentials, regardless of type, share a common namespace, e.g. a credential named 'diego_auth' exists once in CredHub. Credential names are not reservable, so two users updating a credential of the same name will result in updates to the same credential. If you prefer a separate namespace for your credentials, you can add a path prior to the credential name. 

Credentials are typed based on the format of the stored value, value validation and generation procedure. Once a credential type has been set, it can not be updated to a new type. If you mistakenly set the type, you must delete the credential, then set it with the correct type.

---

### <a></a> Get a credential by ID

As described above, credential responses include a unique identifier in the key 'id'. This ID is unique to the credential and value. If your use case requires pinning to a specific value until a manual action is performed, such as a deployment, you can store the credential ID and retrieve the value by ID.

Method: `GET`<br>
URI: `[host]/api/v1/data/[cred id]`

Success Response - 
Status: 200
```json
{
   "name": "/example/password",
   "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
   "type": "password",
   "value": "esTHU1TKyfOkuZjssrlhp56buRZq0n",
   "version_created_at": "2016-01-01T12:00:00Z"
}
```
---


### <a></a> Finding Credentials


Existing credentials in CredHub can be listed by name or path. The response will include a list of the credentials by name and updated date. 

#### <a></a> Finding credentials by partial name

Method: `GET`<br>
URI: `[host]/api/v1/data?name-like=[cred name]`

Success Response - 
Status: 200
```json
{
  "credentials": [
    {
      "name": "/example",
      "version_created_at": "2016-09-30T16:27:58Z"
    },
    {
      "name": "/example/test",
      "version_created_at": "2016-08-30T10:46:36Z"
    },
    {
      "name": "/test/examples",
      "version_created_at": "2016-09-10T00:48:10Z"
    }
  ]
}
```
---


#### <a></a> Finding credentials by path

Method: `GET`<br>
URI: `[host]/api/v1/data?path=[path name]`

Success Response - 
Status: 200
```json
{
  "credentials": [
    {
      "name": "/deploy123/cc/example",
      "version_created_at": "2016-09-30T17:12:34Z"
    },
    {
      "name": "/deploy123/example-test",
      "version_created_at": "2016-09-30T17:12:31Z"
    },
    {
      "name": "/deploy123/password",
      "version_created_at": "2016-09-30T17:12:27Z"
    },
    {
      "name": "/deploy123/ext",
      "version_created_at": "2016-09-30T17:12:25Z"
    }
  ]
}
```
---


### <a></a>Delete a credential

Credentials can be deleted by name. Deleting a credential removes its current and all previous values. 

Method: `DELETE`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Request -
```
[Empty]
```

Success Response - 
Status: 204
```
[Empty]
```
---

### <a></a> Type-Specific Operations

Credential set and generate requests and responses vary by type. The following list of operations show sample requests and responses for each operation, specific to the credential type. 

---

#### <a></a> Password Credentials

Password credentials hold a single string value. The value of a password credential can be statically set or randomly generated by CredHub. 

##### <a></a>Get a password credential

The request to get a credential by name will return an array of all stored values for the named credential, including historical values. If you wish to only retrieve the latest value, the parameter `current=true` will limit the response. 

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
  {
     "name": "/example/password",
     "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
     "type": "password",
     "value": "esTHU1TKyfOkuZjssrlhp56buRZq0n",
     "version_created_at": "2016-01-01T12:00:00Z"
  }]
}
```
---
##### <a></a>Set a static password credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request -
```json
{
  "name": "/example/password",
  "type": "password", 
  "overwrite": true,
  "value": "esTHU1TKyfOkuZjssrlhp56buRZq0n"
}
```

Success Response - 
Status: 200
```json
{
   "name": "/example/password",
   "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
   "type": "password",
   "value": "esTHU1TKyfOkuZjssrlhp56buRZq0n",
   "version_created_at": "2016-01-01T12:00:00Z"
}
```
---
##### <a></a>Set a generated password credential

Method: `POST`<br>
URI: `[host]/api/v1/data`

Request -
```json
{
  "name": "/example/password",
  "type": "password",
  "overwrite": true,
  "parameters":
  {
    "length": 30,
    "exclude_upper": false, 
    "exclude_lower": false, 
    "exclude_number": false, 
    "include_special": true
  }
}
```

Success Response - 
Status: 200
```json
{
   "name": "/example/password",
   "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
   "type": "password",
   "value": "esTHU1TKyfOkuZjssrlhp56buRZq0n",
   "version_created_at": "2016-01-01T12:00:00Z"
}
```
---

#### <a></a> Certificate Credentials

Certificate credentials can hold a CA, intermediate or leaf certificate and consiste of 3 values - certificate, private key and signing CA. The value of a certificate credential can be statically set or generated by CredHub. Statically set certificates only require 1 of the 3 values. Values not provided will be returned as null. Generated certificates may be signed by a CA stored in CredHub or self-signed. 

##### <a></a>Get a certificate credential

The request to get a credential by name will return an array of all stored values for the named credential, including historical values. If you wish to only retrieve the latest value, the parameter `current=true` will limit the response. 

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
  {
    "name": "/example/certificate",
    "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
    "type": "certificate",
    "value":
      {
        "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
        "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
      },
    "version_created_at": "2016-01-01T12:00:00Z"
  }]
}
```
---

##### <a></a>Set a static certificate or CA credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/certificate",
  "type": "certificate",
  "overwrite": true,
  "value":
    {
      "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/certificate",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "certificate",
  "value":
    {
      "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---


##### <a></a>Set a generated certificate credential

Method: `POST`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/certificate",
  "type": "certificate",
  "overwrite": true,
  "parameters":
  {
    "ca": "PivCA",
    "common_name": "pivotal.io",
    "alternative_names": ["dan.pivotal.io", "10.10.10.1"],
    "organization": "Pivotal", 
    "organization_unit": "CF Dev",
    "locality": "San Francisco", 
    "state": "CA",
    "country": "US",
    "key_length": 2048,
    "duration": 365,
    "key_usage": ["digital_signature"],
    "extended_key_usage": ["client_auth", "server_auth"]
  }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/certificate",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "certificate",
  "value":
    {
      "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---

##### <a></a>Set a generated CA certificate credential

Method: `POST`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/certificate",
  "type": "certificate",
  "overwrite": true,
  "parameters":
  {
    "is_ca": true,
    "common_name": "Pivotal CA",
    "organization": "Pivotal", 
    "organization_unit": "CF Dev",
    "locality": "San Francisco", 
    "state": "CA",
    "country": "US",
    "key_length": 4096,
    "duration": 365
  }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/certificate",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "certificate",
  "value":
    {
      "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---

#### <a></a> SSH Credentials

SSH credentials can hold 2 values - public key and private key. The public key is stored in the SSH format of 'ssh-rsa [key] [comment]'. The value of the public key can be appended to the authorized_keys file of the target host.


##### <a></a>Get an SSH credential

The request to get a credential by name will return an array of all stored values for the named credential, including historical values. If you wish to only retrieve the latest value, the parameter `current=true` will limit the response. 

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
  {
    "name": "/example/ssh",
    "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
    "type": "ssh",
    "value":
      {
        "public_key": "ssh-rsa AAAAB3NzaC...p+p3QPLx comment",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----",
        "public_key_fingerprint": "EvI0/GIUgDjcoCzUQM+EtwnVTryNsKRd6TrHAGKJJSI"
      },
    "version_created_at": "2016-01-01T12:00:00Z"
  }]
}
```
---

##### <a></a>Set a static SSH credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/ssh",
  "type": "ssh",
  "value":
    {
      "public_key": "ssh-rsa AAAAB3NzaC...p+p3QPLx comment",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/ssh",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "ssh",
  "value":
    {
      "public_key": "ssh-rsa AAAAB3NzaC...p+p3QPLx comment",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----",
      "public_key_fingerprint": "EvI0/GIUgDjcoCzUQM+EtwnVTryNsKRd6TrHAGKJJSI"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---


##### <a></a>Set a generated SSH credential

Method: `POST`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/ssh",
  "type": "ssh",
  "overwrite": true,
  "parameters":
  {
    "key_length": 2048,
    "ssh_comment": "user@location"
  }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/ssh",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "ssh",
  "value":
    {
      "public_key": "ssh-rsa AAAAB3NzaC...p+p3QPLx user@location",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----",
      "public_key_fingerprint": "EvI0/GIUgDjcoCzUQM+EtwnVTryNsKRd6TrHAGKJJSI"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---

#### <a></a> RSA Credentials

RSA credentials can hold 2 values - public key and private key. The public key is stored in PEM format. The RSA type does not generate a certificate along with the public and private keys. If you require a certificate, you must generate a Certificate credential instead.

##### <a></a>Get an RSA credential

The request to get a credential by name will return an array of all stored values for the named credential, including historical values. If you wish to only retrieve the latest value, the parameter `current=true` will limit the response. 

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
  {
    "name": "/example/rsa",
    "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
    "type": "rsa",
    "value":
      {
        "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
      },
    "version_created_at": "2016-01-01T12:00:00Z"
  }]
}
```
---

##### <a></a>Set a static RSA credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/rsa",
  "type": "rsa",
  "value":
    {
      "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/rsa",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "rsa",
  "value":
    {
      "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---


##### <a></a>Set a generated RSA credential

Method: `POST`<br>
URI: `[host]/api/v1/data`

Request - 
```json
{
  "name": "/example/rsa",
  "type": "rsa",
  "overwrite": true,
  "parameters":
  {
    "key_length": 2048
  }
}
```

Success Response - 
Status: 200
```json
{
  "name": "/example/rsa",
  "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
  "type": "rsa",
  "value":
    {
      "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
  "version_created_at": "2016-01-01T12:00:00Z"
}
```
---

#### <a></a> Value Credentials

Value credentials hold a single string value. A value credential should be used for configuration strings and non-password values. Values credentials must be statically set.

##### <a></a>Get a value credential

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
  {
    "name": "/example/value",
    "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
    "type": "value",
    "value": "/usr/local/app.sh",
    "version_created_at": "2016-01-01T12:00:00Z"
  }]
}
```
---
##### <a></a>Set a static value credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request -
```json
{
  "name": "/example/value",
  "type": "value", 
  "overwrite": true,
   "value": "/usr/local/app.sh"
}
```

Success Response - 
Status: 200
```json
{
   "name": "/example/value",
   "id": "78aaebab-67c5-4e9d-b08b-41205334ec05",
   "type": "value",
   "value": "/usr/local/app.sh",
   "version_created_at": "2016-01-01T12:00:00Z"
}
```
#### <a></a> JSON Credentials

JSON credentials hold an arbitrary JSON object. A value credential should be used for configuration strings and non-password values. Values credentials must be statically set.

##### <a></a>Get a JSON credential

Method: `GET`<br>
URI: `[host]/api/v1/data?name=[cred name]`

Success Response - 
Status: 200
```json
{
  "data": [
    {
      "type": "json",
      "version_created_at": "2017-04-05T20:46:08Z",
      "id": "9142ca0b-9d52-45dd-847d-7fb30ea20e6d",
      "name": "/example/json",
      "value": {
        "key": 123,
        "key_list": [
          "val1",
          "val2",
          "val3"
        ],
        "is_true": true
      }
    }
  ]
}
```
---
##### <a></a>Set a static JSON credential

Method: `PUT`<br>
URI: `[host]/api/v1/data`

Request -
```json
{
  "name": "/example/json",
  "type": "json",
  "value": {
    "key": 123,
    "key_list": [ "val1", "val2", "val3" ],
    "is_true": true
  }
}
```

Success Response - 
Status: 200
```json
{
  "type": "json",
  "version_created_at": "2017-04-05T20:46:08Z",
  "id": "9142ca0b-9d52-45dd-847d-7fb30ea20e6d",
  "name": "/example/json",
  "value": {
    "key": 123,
    "key_list": [
      "val1",
      "val2",
      "val3"
    ],
    "is_true": true
  }
}
```
