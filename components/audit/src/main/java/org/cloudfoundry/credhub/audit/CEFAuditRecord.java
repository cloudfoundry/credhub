package org.cloudfoundry.credhub.audit;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.utils.DefaultVersionProvider;

@Component
@Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
@SuppressWarnings({
  "PMD.TooManyFields",
  "PMD.GodClass",
})
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "This will be refactored into safer non-nullable types"
)
public class CEFAuditRecord {

  // CEF Spec
  private String signatureId;
  private String extension;
  private String credhubServerVersion;

  // Data Inherited (somewhat) from CC
  private String timestamp;
  private String username;
  private String userGuid;
  private String authMechanism;
  private String requestPath;
  private String requestMethod;
  private String result;
  private String sourceAddress;
  private String destinationAddress;
  private Integer httpStatusCode;

  // CredHub-specific Data
  private String resourceName;
  private String resourceUUID;
  private String versionUUID;
  private OperationDeviceAction operation;
  private RequestDetails requestDetails;
  private List<Resource> resourceList;
  private List<Version> versionList;

  @Autowired
  public CEFAuditRecord(final DefaultVersionProvider versionProvider) {
    super();
    this.timestamp = String.valueOf(Instant.now().toEpochMilli());
    this.setCredhubServerVersion(versionProvider.currentVersion());
  }

  public CEFAuditRecord() {
    super();
  }

  @Override
  public String toString() {
    if (resourceList == null || resourceList.isEmpty()) {
      return logRecord().toString();
    }

    final StringBuilder builder = new StringBuilder();
    for (int i = 0; i < resourceList.size(); i++) {
      if (i > 0) {
        builder.append(System.getProperty("line.separator"));
      }
      this.resourceName = resourceList.get(i).getResourceName();
      this.resourceUUID = resourceList.get(i).getResourceId();
      if (versionList != null && !versionList.isEmpty() && versionList.get(i) != null) {
        this.versionUUID = versionList.get(i).getVersionId();
      }
      builder.append(logRecord());
    }

    return builder.toString();
  }

  private StringBuilder logRecord() {
    final int capacityEstimate = 200;
    final StringBuilder builder = new StringBuilder(capacityEstimate);

    final String severity = "0";
    final String cefVersion = "0";
    final String deviceVendor = "cloud_foundry";
    final String deviceProduct = "credhub";

    builder
      .append("CEF:").append(cefVersion).append('|')
      .append(deviceVendor).append('|')
      .append(deviceProduct).append('|')
      .append(credhubServerVersion).append('|')
      .append(signatureId).append('|')
      .append(signatureId).append('|')
      .append(severity).append('|')
      .append("rt=").append(timestamp).append(' ')
      .append("suser=").append(username).append(' ')
      .append("suid=").append(userGuid).append(' ')
      .append("cs1Label=").append("userAuthenticationMechanism").append(' ')
      .append("cs1=").append(authMechanism).append(' ')
      .append("request=").append(requestPath).append(' ')
      .append("requestMethod=").append(requestMethod).append(' ')
      .append("cs3Label=").append("versionUuid").append(' ')
      .append("cs3=").append(versionUUID).append(' ')
      .append("cs4Label=").append("httpStatusCode").append(' ')
      .append("cs4=").append(httpStatusCode).append(' ')
      .append("src=").append(sourceAddress).append(' ')
      .append("dst=").append(destinationAddress).append(' ')
      .append("cs2Label=").append("resourceName").append(' ')
      .append("cs2=").append(resourceName).append(' ')
      .append("cs5Label=").append("resourceUuid").append(' ')
      .append("cs5=").append(resourceUUID).append(' ')
      .append("deviceAction=").append(operation).append(' ');
    if (requestDetails != null) {
      builder
        .append("cs6Label=").append("requestDetails").append(' ')
        .append("cs6=").append(requestDetails.toJSON()).append(' ');
    }
    return builder;
  }

  public void setHttpRequest(final HttpServletRequest request) {
    final StringBuilder pathQuery = new StringBuilder(request.getRequestURI());

    if (!StringUtils.isEmpty(request.getQueryString())) {
      pathQuery.append('?').append(request.getQueryString());
    }

    sourceAddress = request.getHeader("X-FORWARDED-FOR");
    if (sourceAddress == null) {
      sourceAddress = request.getRemoteAddr();
    }

    requestPath = pathQuery.toString();
    requestMethod = request.getMethod();
    signatureId = String.format("%s %s", request.getMethod(), request.getRequestURI());
    destinationAddress = request.getServerName();
  }

  public void setCredhubServerVersion(final String credhubServerVersion) {
    this.credhubServerVersion = credhubServerVersion;
  }

  public String getTimestamp() {
    return timestamp;
  }

  public String getSignatureId() {
    return signatureId;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(final String username) {
    this.username = username;
  }

  public void setUserGuid(final String userGuid) {
    this.userGuid = userGuid;
  }

  public String getAuthMechanism() {
    return authMechanism;
  }

  public void setAuthMechanism(final String authMechanism) {
    this.authMechanism = authMechanism;
  }

  public String getRequestPath() {
    return requestPath;
  }

  public String getRequestMethod() {
    return requestMethod;
  }

  public String getResult() {
    return result;
  }

  public String getSourceAddress() {
    return sourceAddress;
  }

  public String getDestinationAddress() {
    return destinationAddress;
  }

  public Integer getHttpStatusCode() {
    return httpStatusCode;
  }

  public void setHttpStatusCode(final Integer httpStatusCode) {
    this.httpStatusCode = httpStatusCode;
    this.result = HttpUtils.getResultCode(httpStatusCode);
  }

  public String getResourceName() {
    return resourceName;
  }

  public String getResourceUUID() {
    return resourceUUID;
  }

  public String getVersionUUID() {
    return versionUUID;
  }

  public RequestDetails getRequestDetails() {
    return requestDetails;
  }

  public void setRequestDetails(final RequestDetails requestDetails) {
    this.requestDetails = requestDetails;
    this.operation = requestDetails.operation();
  }

  public OperationDeviceAction getOperation() {
    return operation;
  }

  public void setOperation(final OperationDeviceAction operation) {
    this.operation = operation;
  }

  public String getExtension() {
    return extension;
  }

  public void setExtension(final String extension) {
    this.extension = extension;
  }

  public List<Resource> getResourceList() {
    return resourceList;
  }

  public void setResource(final AuditableCredential credential) {
    if (credential == null || credential.getUuid() == null) {
      return;
    }

    this.resourceName = credential.getName();
    this.resourceUUID = credential.getUuid().toString();
  }

  public void setResource(final AuditablePermissionData data) {
    if (data == null || data.getUuid() == null) {
      return;
    }

    this.resourceName = data.getPath();
    this.resourceUUID = data.getUuid().toString();
  }

  public void setVersion(final AuditableCredentialVersion credentialVersion) {
    if (credentialVersion == null || credentialVersion.getUuid() == null) {
      return;
    }

    this.versionUUID = credentialVersion.getUuid().toString();
  }

  public void addResource(final AuditableCredential credential) {
    initResourceList();

    if (credential != null) {
      this.resourceList.add(new Resource(credential.getName(), credential.getUuid().toString()));
    }
  }

  public void addResource(final AuditablePermissionData permissionData) {
    initResourceList();

    if (permissionData != null) {
      this.resourceList.add(new Resource(permissionData.getPath(), permissionData.getUuid().toString()));
    }
  }


  public void addVersion(final AuditableCredentialVersion credentialVersion) {
    if (versionList == null) {
      versionList = new ArrayList<>();
    }

    if (credentialVersion != null) {
      this.versionList.add(new Version(credentialVersion.getUuid().toString()));
    }
  }

  public void initCredentials() {
    this.resourceList = new ArrayList<>();
    this.versionList = new ArrayList<>();
  }

  public void addAllVersions(final List<AuditableCredentialVersion> credentialVersions) {
    credentialVersions.forEach(i -> addVersion(i));
  }

  public void addAllResources(final List<AuditablePermissionData> permissionData) {
    permissionData.forEach(i -> addResource(i));
  }

  public void addAllCredentials(final List<AuditableCredential> list) {
    list.forEach(i -> this.addResource(i));
  }

  private void initResourceList() {
    if (resourceList == null) {
      resourceList = new ArrayList<>();
    }
  }
}
