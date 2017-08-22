# CredHub Documentation

This repository contains documentation pertinent to general application operation and features of CredHub. Additional documentation related to configuration and deployment via BOSH can be found in the [release repo.](https://github.com/pivotal-cf/credhub-release/tree/master/docs)

The API endpoints and associated CLI commands for interactions with CredHub are documented on the [CredHub API and CLI reference site.](https://credhub-api.cfapps.io)

## Product Initiatives

#### In Progress 

* **Authorization via resource access control lists**

    The goal of this initiative is to allow access control lists to be provisioned on credentials and namespaces to allow for granular control of access to credentials.

    **Status**: [Phase 1](authorization-phase1.md) in v1.1.0; In Development

* **Enable secure alternative workflow for delivering service credentials via bind request**

    The goal of this initiative is to provide an alternative workflow for Cloud Foundry service brokers to provide credentials to applications. Additional information can be [found here.](secure-service-credentials.md)

    **Status**: MVP in v1.1.0; In Development

* **Provide performance results for horizontally scaled instances**

    The goal of this initiative is to provide performance results for CredHub as it is scaled to multiple instances. 

    **Status**: In Development

* **Integration with Concourse CI**

    The goal of this initiative is to integrate with Concourse CI to enable credential generation and storage in CredHub.

    **Status**: In Development

***

#### Completed

* **Config server implementation with BOSH Director**

    The goal of this initiative is to provide a [BOSH config server][1] conformant API to allow CredHub to be used for generating and storing BOSH deployment credentials. Additional information can be [found here.](bosh-config-server.md)

    **Status**: Released in v1.0.0

[1]:https://github.com/cloudfoundry/bosh-notes/blob/master/config-server.md

* **Credential access and change logging**

    The goal of this initiative is to provide logs for all access and changes to credentials.

    **Status**: Released in v1.0.0

* **Encryption Key Rotation**

    The goal of this initiative is to provide a method to rotate the encryption key used by CredHub to secure credential data.

    **Status**: Released in v1.0.0

* **Luna HSM encryption provider support**

    The goal of this initiative is to provide support for using a Luna hardware security module (HSM) as an encryption provider.

    **Status**: Released in v1.0.0

* **Integration with Pivotal Ops Manager**

    The goal of this initiative is to integrate with Pivotal Ops Manager to store platform credentials in CredHub to provide the security benefits of CredHub to these users. Additional information can be [found here.](https://docs.pivotal.io/tiledev/credhub.html)

    **Status**: Released in v1.0.0

* **Enable mutual TLS authentication mechanism for applications**

    The goal of this initiative is to allow applications, services and other non-user consumers to authenticate via mutual TLS client certificates. Additional information can be [found here.](mutual-tls.md)

    **Status**: Released in v1.1.0

* **Authorization phase 1 - Secure Service Credentials**

    The goal of this initiative is to enable authorization via ACLs to enable the secure service credential workflow. Additional information can be [found here.](authorization-phase1.md)

    **Status**: Released in v1.1.0

***

#### Future

* **Cloud Foundry credential rotation**

    The goal of this initiative is to enable automated rotation of credentials for components of Cloud Foundry.

    **Status**: Planned

* **Provide pluggable encryption provider interface**

    The goal of this initiative is to provide a pluggable interface for encryption providers to allow the creation and maintenance of encryption providers outside of the core codebase.

    **Status**: Planned

* **Cloud Foundry application credential management**

    The goal of this initiative is to provide a credential management solution for applications of Cloud Foundry.

    **Status**: Planned

* **Encryption-as-a-Service**

    The goal of this initiative is to provide endpoints to allow encryption and decryption of arbitrary data.

    **Status**: Planned


