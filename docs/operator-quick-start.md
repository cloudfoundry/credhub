# BOSH Operator Quick Start 

This quick start guide provides a summary on how to install and configure CredHub, update deployment manifests and interact with credentials via the CLI. Further details on each step can be found in the docs folders of the 'credhub' and 'credhub-release' repos.

## Installation Summary

CredHub is distributed as a BOSH release. To install CredHub on a BOSH Director, the release needs to be colocated on the Director, the CredHub job configurations must be provided and the Director needs to be configured to point to the CredHub API. The CredHub job configurations primarily set the authentication mechanisms, the storage backend and the encryption provider that encrypts data prior to storage.

Once CredHub has been deployed and configured on the Director, any deployments by the Director may use the CredHub variables in place of credential values. 

More information on installation can be [found here.](https://github.com/pivotal-cf/credhub-release/blob/master/docs/bosh-install-with-credhub.md)

## CredHub Credential Types

CredHub enforces a type system to simplify management and generation multi-part credentials. For example, a TLS certificate contains 3 parts - root CA, certificate and private key. If these were stored as separate objects, the association between them may not be clear.

CredHub supports the following credential types: 

* **Value** - This type holds a single string value. It is meant for arbitrary configurations and other non-generated or validated strings. Example manifest reference shown below.
    
    ```
    value: ((example))
    ```

* **JSON** - This type holds an arbitrary json object. It is meant for static configurations with many values where it is not efficient to separate out specific values into typed credentials. Example manifest references shown below. 

    ``` 
    key: ((example.key))
    key2: ((example.key2))
    ```

* **Password** - This type holds a single string value. It is meant for passwords and other random string credentials. Values for this type may be automatically generated. Example manifest reference shown below. 

    ```
    password: ((example))
    ```

* **User** - This type holds username and password values. The response also includes a derived SHA-512 hash of the password. It is meant for username and passwords combination credentials and passwords which require a hashed password value. Values for this type may be automatically generated. Example manifest references shown below.

    ``` 
    username: ((example.username))
    password: ((example.password))
    password_hash: ((example.password_hash))
    ```

* **Certificate** - This type holds an object containing a root CA, certificate and private key. It it meant for key pair applications, such as TLS connections, that utilize a certificate. Values for this type may be automatically generated. Example manifest references shown below.

    ``` 
    certificate_ca: ((example.ca))
    certificate: ((example.certificate))
    private_key: ((example.private_key))
    ```

* **SSH** - This type holds an object containing an SSH-formatted public key and private key. It is meant for key pairs used to establish SSH connections. Values for this type may be automatically generated. Example manifest references shown below.

    ``` 
    ssh-public: ((example.public_key))
    ssh-private: ((example.private_key))
    ```

* **RSA** - This type holds an object containing an RSA public key and private key. It is meant for RSA key pairs (without certificate). Values for this type may be automatically generated. Example manifest references shown below.

    ```
    rsa-public: ((example.public_key))
    rsa-private: ((example.private_key))
    ```

## Deployment Manifest Changes 

When CredHub is enabled on the BOSH Director, it will perform interpolation of credential values into manifests that use the `((variables))` syntax. When the Director encounters a variable using this syntax, it will make requests to CredHub to retrieve the credential value. If the credential does not exist and the release or manifest contains generation properties, the value will be automatically generated. 

The below manifest snippet includes references to two credentials, `example-password` and `example-tls`. When this manifest is deployed, the Director will retrieve the stored credentials and replace them with their stored values. The `example-tls` variables include property accessors, so only the `certificate` and `private_key` components  will be interpolated. 

```yml
---
name: demo-deploy

instance_groups:
  jobs: 
  - name: demo 
    release: demo
    properties:
      demo:
        password: ((example-password))
        tls: 
          certificate: ((example-tls.certificate))
          private_key: ((example-tls.private_key))
```

As previously mentioned, the Director will attempt to generate a credential if it does not exist. To enable this generation feature, the manifest must include generation parameters that define how it should be generated. These generation parameters are defined in the variables section as shown below.  

```yml
---
name: demo deploy 

variables: 
- name: example-password
  type: password
- name: example-ca
  type: certificate
  options: 
    is_ca: true
    common_name: 'Example Certificate Authority'
- name: example-tls
  type: certificate
  options: 
    ca: example-ca
    common_name: example.com

instance_groups:
  jobs: 
  - name: demo 
    release: demo
    properties:
      demo:
        password: ((example-password))
        tls: 
          certificate: ((example-tls.certificate))
          private_key: ((example-tls.private_key))
```


## Variable Namespacing

Deployment manifests often use common variable names, e.g. `((password))`. To avoid variable name collisions between deployments, the Director automatically namespaces variables with the director name and deployment name. For example, the variable `((example-password))` will be stored in CredHub as `/director-name/deployment-name/example-password`. 

If you wish to share credentials across deployments or simply want to use an exact name, prefixing the variable with a `/`, e.g. `((/example-password))`, will cause the Director to use the exact name. 

More information on the BOSH Director integration can be [found here.](https://github.com/cloudfoundry-incubator/credhub/blob/master/docs/initiatives/bosh-config-server.md)

## CLI Usage

The CredHub CLI can be used to interact with CredHub credentials. You must first target the CredHub API using the `api` command. Once targeted, you may login with your user credentials. All subsequent requests will be sent to the targeted CredHub API using the authentication credentials. 

CredHub CLI commands are named based on action - get, set, generate and delete. Each command requires a credential name to be specified using the flag `--name`. Commands which set or generate values must include a credential type using the flag `--type`.

Each command includes a command-specific help menu, which lists its supported commands and a description of each. When a command is type-specific, it will be prefixed with the supported type in the command description, e.g. `-l, --length=     [Password] Length of the generated value (Default: 30)`.


```
user$ credhub -h
Usage:
  credhub [OPTIONS] <command>

Application Options:
      --version  Version of CLI and targeted CredHub API

Help Options:
  -h, --help     Show this help message

Available commands:
  api         Set the CredHub API target to be used for subsequent commands (aliases: a)
  login       Authenticate user with CredHub (aliases: l)
  logout      Discard authenticated user session (aliases: o)
  get         Get a credential value (aliases: g)
  set         Set a credential with a provided value (aliases: s)
  generate    Set a credential with a generated value (aliases: n)
  delete      Delete a credential value (aliases: d)
  regenerate  Set a credential with a generated value using the same attributes as the stored value (aliases: r)
  find        Find stored credentials based on query parameters (aliases: f)
```
