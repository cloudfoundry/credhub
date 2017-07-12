## Product initiatives

* **[Released v1.0.0]** Config server implementation with BOSH Director.

    The goal of this initiative is to provide a [BOSH config server][1] conformant API to allow CredHub to be used for generating and storing BOSH deployment credentials. Additional information can be [found here.](bosh-config-server.md)

* **[MVP v1.1.0; In Development]** Enable secure alternative workflow for delivering service credentials via bind request

    The goal of this initiative is to provide an alternative workflow for Cloud Foundry service brokers to provide credentials to applications. Subsets of this initiative are additionally detailed below. Additional information can be [found here.](secure-service-credentials.md)

* **[Released v1.1.0]** Enable mutual TLS authentication mechanism for applications

    The goal of this initiative is to allow applications, services and other non-user consumers to authenticate via mutual TLS client certificates. Additional information can be [found here.](mutual-tls.md)

* **[MVP v1.1.0, In Development]** Authorization via resource access control lists

    The goal of this initiative is to allow access control lists to be provisioned on credentials and namespaces to allow for granular control of access to credentials.

* **[Released v1.0.0]** Integration with Pivotal Ops Manager

    The goal of this initiative is to integrate with Pivotal Ops Manager to enable CredHub features for users that deploy BOSH and Cloud Foundry via this application.

* **[Planned]** Provide pluggable encryption provider interface

    The goal of this initiative is to provide a pluggable interface for encryption providers to allow the creation and maintenance of encryption providers outside of the core codebase.

* **[Planned]** Enable workflow for application credential management

    The goal of this initiative is to enable a workflow where applications can directly interact with CredHub to generate, store and manage credentials.

* **[Planned]** Integration with Concourse CI

    The goal of this initiative is to integrate with Concourse CI to enable credential generation and storage in CredHub.

* **[Planned]** Cloud Foundry credential rotation

    The goal of this initiative is to enable automated rotation of credentials for components of Cloud Foundry.

* **[Planned]** Cloud Foundry application credential management

    The goal of this initiative is to provide a credential management solution for applications of Cloud Foundry.
