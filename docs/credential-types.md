## CredHub Credential Types

CredHub has introduced credential types to make generation and management of multi-part credentials easier. For example, a TLS certificate contains 3 parts - root CA, certificate and private key. If these were stored as separate objects, the association between them may not be clear.

CredHub supports the following credential types: 

* **Value** - This type holds a single string value. It is meant for arbitrary configurations and other non-generated or validated strings. 

  ```json
  {
    "type": "value",
    "value": "/var/vcap/jobs/credhub/example.sh",
    "updated_at": "2016-10-13T20:59:28Z"
  }
  ```

* **Password** - This type holds a single string value. It is meant for passwords and other random string credentials. Values for this type may be automatically generated. 

  ```json
  {
    "type": "password",
    "value": "nZaowPHTl0CQYVyYA0nV7ayHVulCBU3WTmwJKiZm",
    "updated_at": "2016-10-13T21:03:42Z"
  }
  ```

* **Certificate** - This type holds an object containing a root CA, certificate and private key. It it meant for key pair applications, such as TLS connections, that utilize a certificate. Values for this type may be automatically generated. 

  ```json
  {
    "type": "certificate",
    "value": {
      "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
    "updated_at": "2016-10-13T21:07:37Z"
  }
  ```

* **SSH** - This type holds an object containing an SSH-formatted public key and private key. It is meant for key pairs used to establish SSH connections. Values for this type may be automatically generated. 

  ```json
  {
    "type": "ssh",
    "value": {
      "public_key": "ssh-rsa AAA...PLx user@location",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
    "updated_at": "2016-10-13T21:10:44Z"
  }
  ```

* **RSA** - This type holds an object containing an RSA public key and private key. It is meant for RSA key pairs (without certificate). Values for this type may be automatically generated. 

  ```json
  {
    "type": "rsa",
    "value": {
      "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
    },
    "updated_at": "2016-10-13T21:13:41Z"
  }
  ```

## Consuming CredHub Types in Releases

The BOSH Director will interpolate the key "value" from the credential response for a deployment variable. For example, in a deployment containing the above password credential, BOSH will substitute `"nZaowPHTl0CQYVyYA0nV7ayHVulCBU3WTmwJKiZm"` for the variable. If the same is done with the above certificate credential, the below object will be substituted. 

```json
{
  "ca": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"
}
```

Translated to yaml:
```yaml
  ca: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE------
  certificate: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE------
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY------
```

If you want to leverage a non-string typed credentials, you must update your release to properly consume the new format. The following example shows how to configure a release to accept the above certificate credential. It includes an example to instruct users on how to define the values if they are not using a CredHub credential. 

**Release job spec:**
  ```yml
---
name: demo

properties:
  demo.tls:
    description: "Certificate and private key for TLS connection to API"
    example: |
        ca: |
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
        certificate: | 
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
        private_key: |
          -----BEGIN RSA PRIVATE KEY-----
          ...
          -----END RSA PRIVATE KEY-----
  ```

**Job Template ERB:**
  ```erb
api-ca=<%= p("demo.tls.ca") %>
api-certificate=<%= p("demo.tls.certificate") %>
api-private-key=<%= p("demo.tls.private_key") %>
  ```

**Deployment manifest:**
  ```yml
---
name: demo-deploy
director_uuid: 4c083c13-80b8-4385-9f6f-2c3228334b32

instance_groups:
  properties:
    demo:
      tls: ((demo-tls))
  ```

Updating a release for other types is similar to the example above, being mindful of the key name for each value you wish to consume. 

## Enabling CredHub Automatic Generation in Releases

CredHub and BOSH are integrated to automatically generate missing credential values on deployment. To enable automatic generation, the release or manifest must include an appropriate configuration. 

The sample below demonstrates how a job release spec can be configured to provide generation parameters. The details that should be provided in a release spec are attributes that do not vary per deployment, e.g. type and password attributes.

**Release job spec:**
  ```yml
---
name: demo

properties:
  demo.admin_password: 
    description: "Password for admin user"
    type: password
    parameters: 
      length: 40
      exclude_special: true

  demo.tls:
    description: "Certificate and private key for TLS connection to API"
    type: certificate
    parameters: 
      key_length: 4096
  ```

You may also define these generation parameters in the deployment itself, as shown below. This is best used for generation parameters that are deployment-specific, e.g. a certificate common name. 

**Deployment manifest:**
  ```yml
---
name: demo-deploy
director_uuid: 4c083c13-80b8-4385-9f6f-2c3228334b32

variables: 
- name: demo-password
  type: password
  options: 
    length: 40
    exclude_special: true
- name: demo-tls
  type: certificate
  options: 
    ca: Main-CA
    common_name: example.com
    alternative_names: 
    - example.com
    - www.example.com
    extended_key_usage: 
    - client_auth

instance_groups:
  properties:
    demo:
      admin-password: ((demo-password))
      tls: ((demo-tls))
  ```
