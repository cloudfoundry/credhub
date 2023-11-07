# Credhub Security FAQ
 
## Overview
CredHub is a component designed for centralized credential management in Cloud Foundry. It handles the following operations for credentials: generation, storage, lifecycle management, and access.  Pivotal Cloud Foundry Compliance and Security Guild can be found online at  https://docs.pivotal.io/pivotalcf/2-6/security/index.html

## What cryptographic libraries are in place?
* Java JCA/JCE
* Java 17 javax.crypto
* bouncycastle FIPS 1.0
* OpenSSL on the stemcell

## What reliability and availability characteristics exist?
It is a credential management service that is centralized and encrypted.  It may be deployed in an HA fashion. When Credhub is BOSH deployed, a health check is used to ensure availability.

## What standard security approaches are implemented?
Access to CredHub is controlled via an OAuth 2.0 server, UAA.  Supports mTLS v1.2 for mutual client & server authentication. Communication between peers uses x.509 certificates.


## How can cryptography be tested?
A tester may use the CredHub API to exercise product cryptographic functions, in addition, a tester may validate the at-rest storage by logging into the CredHub database to see that credentials are not in plain text. Manifests referencing CredHub values do not show plain text password. Reviewers may inspect bosh manifest to confirm.  Actually being able to fetch credentials and have a successful deployment of vm’s in the foundation.


## What cryptographic key management techniques and standards does the product support? 
AES 256 GCM is supported for encryption.  NIST Special Publication 800-90A Revision 1, section 10.1 is used during HSM-based key generation.  PKCS standard for PKI (PEM, x.509).  Default configuration is TLS v1.2: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

## How are Keys internally managed?
If CredHub's third-party integration with a Luna SafeNet HSM is enabled, then CredHub has no knowledge of key values.  If CredHub is started in internal encryption mode, CredHub deterministically generates a site-specific AES256 key on startup. CredHub concatenates a user-defined password from its configuration file with a randomly-generated salt stored in its database and hashes the resulting string to deterministically generate an AES256 key, which it holds in memory for the lifetime of the server.


## How are privileged users prevented from compromising cryptographic keys?
Key material is handled by the platform operator. The CredHub service and the bosh director both provide accountability of operator actions via audit logs of deployment and CRUD events.  CredHub API service implements an ACL system to provide minimum privileged access based on the operator authentication.

## How are random numbers generated and what is entropy source?
Java JCA/JCE on top of Linux OS, /dev/urandom.  We use HSM random for generation if available SHA1PRNG. For entropy source, Java JCA/JCE provider is used, but ultimately Linux OS /dev/urandom, or HSM.

## What are the symmetric cipher algorithms and modes of operation supported?
CredHub internal provider implements:  AES 256 GCM.  

## What are the public key algorithms supported?
RSA.  2048 as default modulus

## What are the hash function algorithms supported?
SHA256

## What external key management hardware vendor products are supported?
Luna Safenet HSM (AWS CloudHSM Classic)

## Does the user create and manage all cryptographic keys?
Users may use CredHub to store keys that they have generated off-board.  CredHub also has the option to do automatic key generation for secrets required in bosh manifests.

## What is the Password-Based Encryption (PBE) standard?
PBKDF2WithHmacSHA384

## What requirements are placed on PBE password inputs? 
When Luna HSM is used, password generation is delegated to Luna.  When generation is done internally,  PBKDF2WithHmacSHA384 is invoked with no truncation of password string supplied by the caller.   When internal, it goes through 100K iterations

## What signature algorithm is used when generating certificates?
[SHA256withRSA](https://github.com/cloudfoundry-incubator/credhub/blob/master/components/encryption/src/main/java/org/cloudfoundry/credhub/config/BouncyCastleProviderConfiguration.java#L23)