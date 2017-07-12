## Spring Integration

Service brokers and client applications written in Java can use higher-level libraries to store credentials in CredHub and interpolate VCAP_SERVICES in client applications. 

### Common Components

#### Spring CredHub

[Spring CredHub][1] is a project that provides CredHub integration for Java and Spring applications. The main library is Spring CredHub Core, which provides Java bindings for the CredHub API. This library is intended to provide full coverage of the CredHub API - all operations on all credential types. The library also includes easy configuration for Spring apps and manages authentication on behalf of apps that integrate with CredHub. 

[1]:https://projects.spring.io/spring-credhub/

#### Java Buildpack

Service brokers and client applications running on the Cloud Foundry platform use mutual TLS to authenticate to CredHub. The certificate and public key necessary for applications to configure TLS are provided in `CF_INSTANCE_CERT` and `CF_INSTANCE_KEY` environment variables that are automatically made available to applications running in Diego-managed containers. 

The Cloud Foundry Java Buildpack installs and configures the Java runtime environment for applications deployed to Cloud Foundry. Starting with versions 3.17 and 4.1, the Java Buildpack will automatically configure the JRE to use the mutual TLS certificate and key provided in application containers. Applications staged with Java Buildpack do not require any additional configuration to authenticate to CredHub. 

#### Service Brokers

Service brokers written using Java and Spring can use Spring CredHub to easily store credentials in the binding flow. A service broker would first add Spring CredHub as a dependency and configure a CredHubTemplate as shown on the project page. 

Once the CredHubTemplate bean has been configured and is available to the service broker application code, a method like the example below could be used to store the raw credentials created by the broker while processing a binding request and build new credentials containing a CredHub reference.

```
/** 
 * Store the provided credentials in CredHub. 
 * 
 * @param bindingGuid the GUID of the binding, provided by Cloud Controller
 * @param appGuid the GUID of the application being bound to the service,
 *                provided by Cloud Controller
 * @param credentials the “raw” credentials for the service binding, 
 *                    provided by the service broker
 * @return new credentials containing the CredHub reference that should
 *         be returned to Cloud Controller by the service broker
 */
Map<String, Object> writeCredentials(String bindingGuid, 
                                     String appGuid, 
                                     Map<String, Object> rawCredentials) {
    ServiceInstanceCredentialName credentialName = 
        ServiceInstanceCredentialName.builder()
            .serviceBrokerName("my-service-broker")
            .serviceOfferingName("my-service")
            .serviceBindingId(bindingGuid)
            .credentialName("credentials")
            .build();

    AdditionalPermissions permission = AdditionalPermissions.builder()
        .app(appGuid)
        .operation(AdditionalPermission.Operation.READ)
        .build();


    JsonCredentialRequest request = JsonCredentialRequest.builder()
        .name(credentialName)
        .additionalPermission(permission)
        .value(rawCredentials)
        .build());

    credHubTemplate.write(request);

    Map<String, Object> credHubCredentials = new HashMap<>(1);
    credHubCredentials.put("credhub-ref", 
                           "((" + credentialName.getName() + "))");
    return credHubCredentials;
} 
```

This example code uses the GUID of the application that is being bound to the service instance to set up READ permissions for the application. 

#### Client Applications

Spring Cloud Connectors is a library that is used by Spring applications to consume bound services on Cloud Foundry. The library parses the JSON in the VCAP_SERVICES environment variable into Java objects that applications can query and use via a low-level Java API. It also has the ability to create Spring beans for well-known connection types (e.g relational databases, MongoDB, Redis, RabbitMQ). Extension libraries provide the ability to create Spring beans and configure applications to consume additional services including Spring Cloud Services, Single Sign-On Service, and GemFire.

Applications already using Spring Cloud Connectors will simply need upgrade to a newer version of the library and add a dependency on a Connectors extension library. With no code changes to the application, any CredHub references in VCAP_SERVICES will automatically get interpolated.

Example changes to a Maven pom.xml file: 
```
<dependencies>
    ...
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-core</artifactId>
         <version>1.2.5.RC1</version>
      </dependency>
      <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-spring-service-connector</artifactId>
        <version>1.2.5.RC1</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-cloudfoundry-connector</artifactId>
        <version>1.2.5.RC1</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.credhub</groupId>
        <artifactId>spring-credhub-cloud-connector</artifactId>
        <version>1.0.0.M1</version>
    </dependency>
</dependencies>

<repositories>
    ...
    <repository>
        <id>spring-milestone-repository</id>
        <name>Spring Milestone Repository</name>
        <url>https://repo.spring.io/libs-milestone/</url>
    </repository>
</repositories>
```

