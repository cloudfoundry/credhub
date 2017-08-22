# Authorization Phase 1 - Secure Service Credentials

### Description

Authorization is a large and complex body of work. To reduce risk and gain early feedback, we will implement authorization in CredHub in a series of phases. At the end of each phase, we will validate that the solution meets expectations and solves a real problem. During the phased implementation, enforcement of ACLs will be optional to allow users to continue with the existing approach if that is preferred. 

The target use-case for phase 1 of CredHub authorization is in controlling access to service broker-provisioned app credentials. This workflow involves a service broker writing credentials to CredHub during a bind request, then passing back the credential name to the application for their retrieval from CredHub. This phase must provide restrictions on the ability to read and change credentials based on users' [authenticated identities.](authentication-identities.md) For example, if SB1 writes a credential for app1, then SB2 and app2 cannot access the credential. More information on this use case is [described here.](secure-service-credentials.md)

### Motivation

[See here](secure-service-credentials.md#motivation) for motivations for the secure service credential delivery workflow.

### Implementation

Phase 1 will implement the baseline structure for access control decision making, authenticated identities, logging and minimal convenience functionality to enable the above use case. This use case assumes access controls are set programatically and not exposed to end users. For this reason, the functionality delivered at the end of this phase may not be suitable for use cases that require manual ACL management. 

The components of functionality are detailed below. 

#### Access control based on credentials ACLs

Ability to perform an operation will be determined based on the identity of the requestor, the operation and the ACL of the resource. ACLs are expressed as allowances, so if a requestor does not have an explicit allowance, they will be denied access. For example, if user 'dan' requests to read credential 'password', they would be allowed to read if the 'password' ACL contains an entry for 'actor: dan; operation: read'. 

##### Supported Resources 

Resources in CredHub for access control are defined as named credentials. Each named credential contains one ACL, which consists of one or more access entries. This structure allows the finest-grained control in CredHub to be a named credential. Credential versions cannot be separately controlled, they assume the access control of their named credential. 

##### Supported Actors (aka authenticated identities)

The actor in an authorization decision will be pulled from the provided authentication method assertion. This will be limited to the primary identity and issuer type in phase 1. The following identifiers will be captured per method. 

UAA - client_credentials grant
* Field: JWT client_name
* Example: `uaa-client:director_to_credhub`

UAA - password grant
* Field: JWT user_id
* Example: `uaa-user:2ae1621a-bb35-4bb7-946a-4761d3b16a04`

mTLS - application
* Field: Organizational Unit
* Example: `mtls-app:f4ecdf88-951a-4a1b-ac09-a8c294d3c2ae`

User metadata, groups, compound identities and other related work will be reviewed in future phases.  

##### Supported Operations

| Operation | Description | Controlled Interactions |
| --- | --- | --- |
| read | Controls ability to read a credential value | Get credential by name |
| | | Get credential by ID |
| | | Get a credential via interpolate endpoint |
| write | Controls ability to modify a credential value | Set a credential by name |
| | | Generate a credential by name |
| | | Regenerate a credential by name |
| delete | Controls ability to delete a credential | Delete a credential by name |
| read_acl | Controls ability to read a credential's ACL | Get ACL by credential name |
| write_acl | Controls ability to modify a credential's ACL | Add entry to credential ACL |
| | | Delete entries from credential ACL |

##### Sample ACL
```
{
    "credential_name": "/example-credential",
    "permissions": [
        {
            "actor": "uaa-client:example_client",
            "operations": [
                "read",
                "write",
                "delete",
                "read_acl",
                "write_acl"
            ]
        },
        {
            "actor": "uaa-user:eaceb5af-cf1f-4645-af80-857fe1f80477",
            "operations": [
                "read"
            ]
        }
    ]
}
```

The folder or path of a credential is not contemplated in this phase. This means a user can provision a credential at any location, assuming no name conflicts exist. There also is no control over a user's ability to list credential names, e.g. the find command, in this phase. 

#### Manual ACL management

Permissions can be managed in phase 1 via [requests to the API.][1] New access can be set on credentials [as they are created][2] or [after the fact][3]. Permission modification is required per credential, without inheritance or the ability to cascade changes.

[1]:https://credhub-api.cfapps.io/#permissions
[2]:https://credhub-api.cfapps.io/#type-value19
[3]:https://credhub-api.cfapps.io/#add-permissions

#### Logging for all ACE and ACL operations

All operations to get, modify or delete access control lists will be logged in the operation audit logs and CEF security events log file.  

#### Access granted to creator of credential

The creator of a credential will be automatically granted full permission. In a grand majority, if not all, cases this is expected behavior when creating a resource. This functionality will introduce a default restricted-access behavior for all credentials. 

#### Migration plan

Credentials that exist prior to the ACL feature work (before v1.1.0), and therefore contain no access control entries, will bypass ACL enforcement. This will allow a gradual migration to new credentials and manual provisioning of permissions on existing resources to gain ACL enforcement. This bypass logic will be phased out after a few compatibility releases. 

### Configuration

Access control to enable the above features can be enabled by deploying CredHub v1.1.0+ with the [manifest property][4] `authorization.acls.enabled` set to `true`.

[4]:https://github.com/pivotal-cf/credhub-release/blob/1.2.0/jobs/credhub/spec#L140-L142
 
