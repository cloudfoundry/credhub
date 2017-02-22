This document introduces CredHub, a component designed for centralized credential management in Cloud Foundry. Credentials exist in many places in the Cloud Foundry ecosystem. Applications consume service credentials through the VCAP_SERVICES environment variable. CF components in the management backplane use them for authenticated communications with other components. It is common for a CF installation to have hundreds of active credentials, and all of them are important in their own way. It is widely known that leaked credentials are a common culprit in data breaches. It behooves all of us in the community to do what we can to improve how the CF ecosystem manages credentials.

CredHub is a single component that can address several scenarios in the CF ecosystem. At the highest level, CredHub centralizes and secures credential generation, storage, lifecycle management, and access. 

##Key Scenarios
The following list includes scenarios that CredHub can address. CredHub will not realize all of these scenarios at initial release, however, this is intended to provide an idea of the scope of the project.

* **Remove credentials from BOSH manifests stored in source repositories.** CredHub implements the config server API spec, which enables the BOSH Director to merge credentials into BOSH manifests later in the lifecycle. This reduces the requirement for stringent read-access permissions on source code repositories.
* **Conceal service credentials from the Cloud Controller and the ‘cf env’ command.** We have received consistent feedback from organizations that want to avoid revealing sensitive service credentials to any CF component that doesn’t absolutely need access to them.
* **Allow organizations the option to separate credential management from installation operations and management.** The goal of this type of separation of duties is to move credential management out of the everyday workflow of CF operations and management. If we move credentials to CredHub, installation administrators can grant security administrators access to CredHub, thereby offloading that responsibility to another group.
* **Provide a key building block for frequent credential rotation.** This service will provide an installation-wide certificate authority, a single source for credential and key generation and provisioning, as well as introducing an authoritative source for credential history.


##Basic Architecture
The first form of CredHub consists of a REST API and a CLI. The REST API conforms to the Config Server API spec. CredHub is an OAuth2 resource server, so it’s natural for UAA to provide core authentication and federation capabilities. The REST API fronts a pluggable storage and encryption system. CredHub works with Hardware Security Modules (HSMs) and development will focus on providing features and security for operation in a production setting. 

![Basic Architecture](images/basic-architecture.png) 

##Proposed Scope
###Securing Data for Storage
CredHub relies on a backing store for persistent storage. Sensitive data that is written or accessed from the data store will be encrypted and decrypted via CredHub to prevent disclosure in the event the data store is stolen. 

An encryption provider is responsible for performing cryptographic operations on the data. The choice of encryption provider is configurable to allow users to select a provider that fits their risk profile. CredHub includes a software based AES encryption provider as well as clients for external providers such as hardware security modules. 

Data storage is not a direct responsibility of CredHub. The product provides clients and data migrations for supported relational database types, however, database deployment, maintenance, backup/restore and other configurations are not managed by CredHub.

###Authentication
CredHub trusts UAA, and UAA provides federation with enterprise identity providers. Due to the need for resource-level authorization control, we use identities from UAA tokens for authorization decisions, not UAA scopes or authorities. 

###Authorization
Authorization is a vital part of CredHub. The authorization model is intended to be friendly to the requirements of CF apps and components. The authorization model considers a simplified authorization decision to consist of three parts: an actor, an operation and a resource. With this model, an administrator may configure any combination of access for a given user performing any operation on a resource.

Resources in CredHub are organized in a namespace, and flexible ACLs dictate access to the namespace. To lessen the burden of provisioning authorization control entries for each resource, the system will provide inheritance from a parent "directory". For example, a user may provision "/service1/" with full access to client "service1". This client would then be able to perform all operations on resources within this path.

A full description of authorization capabilities is beyond the scope of this document. We will present ideas in the coming weeks.

###Access and Change Logging
CredHub logs all actor activities. Audit logs are provided in the database and as a common event format log file. Standard services, such as the syslog-release may be used to forward logs to external log aggregators. 

###Data Typing
CredHub enforces typing for all stored credentials. Credential types provide an expected credential object format for consumers when generating or consuming multi-part credentials. An example of a credential type is a 'certificate' credential, which contains values for CA, certificate and private key.

###Credential Generation
CredHub can generate credentials, including passwords, ssh keys, rsa key pairs and x509 certificates. The process for generating credentials may be automated by clients via the API or CLI using known component generation configurations.

CredHub maintains a simple certificate authority structure which allows certificates to be generated and signed by any number of stored CA key pairs. External credential generation, such as MySQL and IaaS user provisioning, will be pluggable to allow contributions of add-ons without requiring dedicated time from the core team or integration into the core codebase.

###Credential Metadata
CredHub stores credential metadata such as age, TTL, type, generation parameters and method to rotate. This  provides administrative awareness and may be exposed to clients to enforce lifecycle events for stored credentials. 

###Credential Versioning
CredHub maintains historical values for all credentials. On change, a new resource is created to reflect the latest credential value without losing historical values. 

In the future, credential status may represent current and future credential values. This functionality will prevent a user's preliminary changes in an environment from affecting the functionality of the dependent components. A user will be able to configure future state values in CredHub that persist in a pending state until they chose to make the future values active. 

##BOSH Manifest Implementation
CredHub can be the BOSH config server implementation.  For this use case, you may also choose to deploy all components on the BOSH Director as illustrated below. 

![BOSH Director VM Architecture](images/bosh-director-architecture.png) 

This implementation demonstrates some of the key scenarios described above. The difference in example  manifests shown below demonstrate the streamlined experience for operators and the clear separation between deployment configuration and credential management. The variables in the new manifest may be references to existing stored credentials or (if they don't exist) values may be generated automatically by CredHub. 

Existing manifest: 
```
properties: 
  sample-job:
    users:
    - user: test 
      password: hzbS0yLTItNS05MIIBIjANBgkqhkiG
    ssl:
      certificate: |
        -----BEGIN CERTIFICATE-----
        MIIDIzCCAgugAwIBAgIJAIBWx2J4fpPzMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNV
        BAMTCjEwLjAuMC4xNTAwHhcNMTYwODIyMDQyNDA4WhcNMTYwOTIxMDQyNDA4WjAV
        ...
        Ji4PTyGXgMt+2MjWM7Qx9bBkHtnrgZvTZ1C4+W9DSX16FQTpnTBRd/qZUFLvZLrc
        r0MYui7lZuO7mQnV9dZItNpX16P/WmBgWT13PjyTMRg/R6gujI1x
        -----END CERTIFICATE-----
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAy/dhqB3MPBUafDy9pA9eRTMhPHRv3eAH/J8F9byNffpuf5CC
        Cweu8gwW76jlBf9PVEvFESL4a9Ga9DGRVbJ6oHSEGBuMr7hLynlyqMPeM/0iG12u
        ...
        M0dwUpIYnvr3z1h/5wemb3/RqjdQxEsRuhMtDIOLt7IYV5Ya+gie48ZY4wbDsNiA
        76c6bg/lsFIkh0J14Qi/5AgRTH1TbyqklUw5An44RfMaoDHr0N6FmQ==
        -----END RSA PRIVATE KEY-----
    ssh_access: 
      public_key: ssh-rsa AAAAB3Nz...49oOSO0hxc
```

New manifest: 
```
properties: 
  sample-job:
    users:
    - user: test 
      password: ((sample/users/test))
    ssl: ((sample-certificate))
    ssh_access: 
      public_key: ((sample-ssh.public_key))
```

The variable ((sample-certificate)) demonstrates the advantage of using typed credentials. This credential provides values for the CA, certificate and private key to the job as a single object.  Similarly, ((sample-ssh.public_key)) demonstrates the ability to access a single value from within a credential object using a dot accessor. Treating these values as one credential simplifies generation and the need to manually maintain their association. 
