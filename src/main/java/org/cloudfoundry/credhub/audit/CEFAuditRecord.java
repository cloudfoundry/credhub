package org.cloudfoundry.credhub.audit;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.entity.RequestDetails;
import org.cloudfoundry.credhub.config.VersionProvider;
import org.cloudfoundry.credhub.entity.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

@Component
@Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class CEFAuditRecord {

  private static final String CEF_VERSION = "0";
  private static final String DEVICE_VENDOR = "cloud_foundry";
  private static final String DEVICE_PRODUCT = "credhub";
  private static final String SEVERITY = "0";
  private static final String CS1_LABEL = "userAuthenticationMechanism";
  private static final String CS2_LABEL = "resourceName";
  private static final String CS3_LABEL = "result";
  private static final String CS4_LABEL = "httpStatusCode";
  private static final String CS5_LABEL = "resourceUuid";
  private static final String CS6_LABEL = "requestDetails";

  private UUID uuid;

  // CEF Spec
  private String signatureId, extension, credhubServerVersion;

  // Data Inherited (somewhat) from CC
  private String timestamp, username, userGuid, authMechanism, requestPath,
      requestMethod, result, sourceAddress, destinationAddress;
  private Integer httpStatusCode;

  // CredHub-specific Data
  private String resourceName, resourceUUID;
  private OperationDeviceAction operation;
  private RequestDetails requestDetails;
  private List<Credential> credentialList;

  @Autowired
  public CEFAuditRecord(RequestUuid requestUuid, VersionProvider versionProvider) {
    this.timestamp = String.valueOf(Instant.now().toEpochMilli());
    this.uuid = requestUuid.getUuid();
    this.setCredhubServerVersion(versionProvider.currentVersion());
  }

  public CEFAuditRecord() {
  }

  @Override
  public String toString() {
    if(credentialList == null || credentialList.isEmpty()){
      return logRecord().toString();
    }

    StringBuilder builder = new StringBuilder();
    for(int i = 0; i < credentialList.size(); i++){
      if(i > 0){
        builder.append(System.getProperty("line.separator"));
      }
      this.resourceName = credentialList.get(i).getName();
      this.resourceUUID = credentialList.get(i).getUuid().toString();
      builder.append(logRecord());
    }

    return builder.toString();
  }

  private StringBuilder logRecord(){
    StringBuilder builder = new StringBuilder();
    builder.append("CEF:").append(CEF_VERSION).append("|");
    builder.append(DEVICE_VENDOR).append("|");
    builder.append(DEVICE_PRODUCT).append("|");
    builder.append(credhubServerVersion).append("|");
    builder.append(signatureId).append("|");
    builder.append(signatureId).append("|");
    builder.append(SEVERITY).append("|");
    builder.append("rt=").append(timestamp).append(" ");
    builder.append("suser=").append(username).append(" ");
    builder.append("suid=").append(userGuid).append(" ");
    builder.append("cs1Label=").append(CS1_LABEL).append(" ");
    builder.append("cs1=").append(authMechanism).append(" ");
    builder.append("request=").append(requestPath).append(" ");
    builder.append("requestMethod=").append(requestMethod).append(" ");
    builder.append("cs3Label=").append(CS3_LABEL).append(" ");
    builder.append("cs3=").append(result).append(" ");
    builder.append("cs4Label=").append(CS4_LABEL).append(" ");
    builder.append("cs4=").append(httpStatusCode).append(" ");
    builder.append("src=").append(sourceAddress).append(" ");
    builder.append("dst=").append(destinationAddress).append(" ");
    builder.append("cs2Label=").append(CS2_LABEL).append(" ");
    builder.append("cs2=").append(resourceName).append(" ");
    builder.append("cs5Label=").append(CS5_LABEL).append(" ");
    builder.append("cs5=").append(resourceUUID).append(" ");
    builder.append("deviceAction=").append(operation).append(" ");
    if (requestDetails != null) {
      builder.append("cs6Label=").append(CS6_LABEL).append(" ");
      builder.append("cs6=").append(requestDetails.toJSON()).append(" ");
    }
    return builder;
  }

  public void setHttpRequest(HttpServletRequest request) {
    StringBuilder pathQuery = new StringBuilder(request.getRequestURI());

    if (!StringUtils.isEmpty(request.getQueryString())) {
      pathQuery.append("?").append(request.getQueryString());
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

  public String getCredhubServerVersion() {
    return credhubServerVersion;
  }

  public void setCredhubServerVersion(String credhubServerVersion) {
    this.credhubServerVersion = credhubServerVersion;
  }

  public String getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(String timestamp) {
    this.timestamp = timestamp;
  }

  public String getSignatureId() {
    return signatureId;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getUserGuid() {
    return userGuid;
  }

  public void setUserGuid(String userGuid) {
    this.userGuid = userGuid;
  }

  public String getAuthMechanism() {
    return authMechanism;
  }

  public void setAuthMechanism(String authMechanism) {
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

  public void setResult(String result) {
    this.result = result;
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

  public void setHttpStatusCode(Integer httpStatusCode) {
    this.httpStatusCode = httpStatusCode;
    this.result = Utils.getResultCode(httpStatusCode);
  }

  public String getResourceName() {
    return resourceName;
  }

  public void setResourceName(String resourceName) {
    this.resourceName = resourceName;
  }

  public String getResourceUUID() {
    return resourceUUID;
  }

  public void setResourceUUID(String resourceUUID) {
    this.resourceUUID = resourceUUID;
  }

  public RequestDetails getRequestDetails() {
    return requestDetails;
  }

  public void setRequestDetails(RequestDetails requestDetails) {
    this.requestDetails = requestDetails;
    this.operation = requestDetails.operation();
  }

  public OperationDeviceAction getOperation() {
    return operation;
  }

  public void setOperation(OperationDeviceAction operation) {
    this.operation = operation;
  }

  public String getExtension() {
    return extension;
  }

  public void setExtension(String extension) {
    this.extension = extension;
  }

  public void setCredential(Credential credential) {
    if(credential == null || credential.getUuid() == null){
      return;
    }

    this.resourceName = credential.getName();
    this.resourceUUID = credential.getUuid().toString();
  }

  public void addCredential(Credential credential) {
    if(credentialList == null){
      credentialList = new ArrayList<>();
    }

    this.credentialList.add(credential);
  }

  public void initCredentials(){
    this.credentialList = new ArrayList<>();
  }
}


