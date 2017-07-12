# Secure Service Credential Delivery

### Description
Cloud Foundry implements a mechanism for provisioning services known as a [service broker][1]. This implementation enables a self-service model that allows developers to provision access to a service, e.g. a database, for use by an application. This is also referred to as binding an application to a service. The underlying mechanics of provisioning a tenant or deploying a dedicated instance of the service for the application are transparent to the developer.  

A simplified view of the workflow for binding an application to a service is shown below.

<img src="../images/current-binding-workflow.png">

1. User requests to bind Service1 to App1
2. Cloud Controller send bind request to Service Broker 
3. Service Broker provisions service credentials with service 
4. Service returns credential values 
5. Service Broker returns 'VCAP_SERVICES' data containing credential values to Cloud Controller
6. Cloud Controller sends 'VCAP_SERVICES' data containing credential values to Diego
7. Diego places data containing credential values into App1 environment
8. Success response
9. Success response
10. Success response

[1]:https://docs.cloudfoundry.org/services/overview.html

### Motivation
The service binding workflow is a very compelling feature for operators and developers. However, some users have expressed concerns about the delivery workflow of service credentials in the current model.

* Leaking environment variables to logs increase risk of disclosure

    Developers often need to write environment variables to logs for debugging. If environment variables are written to logs for an application that has bound to a service, the service credentials will be included in logs. Log files tend to have less access control than application environments, so this increase the likelihood of disclosing the credentials. 

* Transiting credentials between components increases risk of disclosure

    The current model passes a service credential from the service broker through the cloud controller to the runtime to be places in the application environment. As more components interact are involved, the risk of disclosure increases.

* Rotating credentials delivered via the environment require container recreation

    If you wish to rotate a credential delivered via environment variables, the container must be recreated. This requirement creates friction in an environment with short-lived credentials, because credential rotation incurs an overhead cost on the plaform due to increased lifecycle events. This encourages long-lived credentials, which increases the risk of disclosure.  

### Implementation

To address the above concerns, we have created an alternative workflow that allows service brokers to write and applications to retrieve service credentials directly via CredHub. This modified workflow reduces the requests containing credentials to only those essential to the process.

#### Updated Service Workflow 

<img src="../images/secure-binding-workflow.png">

1. User requests to bind Service1 to App1
2. Cloud Controller send bind request to Service Broker 
3. Service Broker provisions service credentials with service 
4. Service returns credential values 
5. Service Broker sets credential value into CredHub with access control allowing App1 to read the value
6. Success response
7. Service Broker returns 'VCAP_SERVICES' data containing CredHub reference to Cloud Controller
8. Cloud Controller sends 'VCAP_SERVICES' data containing CredHub reference to Diego
9. Diego places data containing CredHub reference into App1 environment
10. Success response
11. Success response
12. Success response

#### Application Workflow 

After the bind workflow has completed, the app is able to access the credential values on-demand via a request to CredHub. This process may be automated using client libraries, such as [Spring CredHub.](https://projects.spring.io/spring-credhub/)

#### Authentication 

All interactions with CredHub must be authenticated. CredHub supports authentication via [UAA][2] and [mutual TLS](mutual-tls.md). 

Service brokers that are deployed as Cloud Foundry applications are recommended to use the [instance identity credentials][3]. Service brokers that are deployed as a platform instance or third party service must use a UAA client credential. 

Applications must authenticate with CredHub using the application instance identity credentials. 

Instance identity credentials are provisioned and rotated automatically in the application container. CredHub will validate the [authenticated identity](authentication-identities.md), signing authority, validity dates and presence of x509 extension Extended Key Usage 'Client Authentication' during the authentication workflow. 

[2]:https://github.com/cloudfoundry/uaa
[3]:https://github.com/cloudfoundry/diego-release/blob/master/docs/instance-identity.md

#### Authorization

Credential access in CredHub is controlled via access control lists. Each credential contains a list of permitted operation allowance for users. For each request, the ACL is validated to determine whether a user is authorized to perform the requested operation. 

When a new credential is created, the creator is granted full access to the credential. In this workflow, the service broker will originate all service binding credentials and, therefore, receive full access. In the request to store the credential, the service broker will include an entry to authorize the app in the bind request to read the credential value. 

This authorization workflow will enforce appropriate controls so that only the originating service broker and bound app are able to access the stored service credentials.

#### Credential Naming Scheme 

To avoid name collisions and aid in authorization, a scheme has been established for service brokers storing credentials in CredHub. The scheme is shown below: 

`/c/client-identifier/service-identifier/binding-guid/credential-name`

* `/c/` - This is a static identifier to organize client credentials
* `/client-identifier/` - This provides a unique namespace for each client
* `/service-identifier/` - This separates credentials by service where a service broker is brokering multiple services
* `/binding-guid/` - The binding guid is a unique identifier for a bind request
* `/credential-name` - The name of the credential in a bind request

Example: `/c/p-spring-cloud-services/p-config-server/385fab51-ede9-43fb-878a-2fc9346a8c3e/config-credential`

#### Interpolation Endpoint

CredHub provides a convenience endpoint that returns an interpolated `VCAP_SERVICES` object from a request that contains CredHub variable placeholders. This allows applications and frameworks to continue using the familiar `VCAP_SERVICES` object without implementing variable interpolation logic. 

This endpoint accepts `VCAP_SERVICES` content in a request and returns the content with credential values interpolated into the request JSON. The variable provided must be located at `VCAP_SERVICES.*[*].credentials.credhub-ref` and the variable type must be 'json'. More information on this endpoint [can be found here.](https://credhub-api.cfapps.io/#interpolate-endpoint-beta)

### Deployment Configuration

(Coming Soon) 

