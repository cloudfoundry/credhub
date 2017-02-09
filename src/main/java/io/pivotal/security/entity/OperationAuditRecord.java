package io.pivotal.security.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;

@SuppressWarnings("unused")
@Entity
@Table(name = "OperationAuditRecord")
@EntityListeners(AuditingEntityListener.class)
public class OperationAuditRecord {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  private String hostName;
  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  private Instant now;

  private String credentialName;
  private String operation;
  private String path;
  private String queryParameters;
  private long tokenIssued;
  private long tokenExpires;
  private boolean success = true;
  private String uaaUrl;
  private String userId;
  private String userName;
  private String requesterIp;
  private String xForwardedFor;
  private String clientId;
  private String scope;
  private String grantType;
  private String method;
  private int statusCode;

  public OperationAuditRecord() {
  }

  public OperationAuditRecord(
      Instant now,
      String credentialName,
      String operation,
      String userId,
      String userName,
      String uaaUrl,
      long tokenIssued,
      long tokenExpires,
      String hostName,
      String method,
      String path,
      String queryParameters,
      int statusCode,
      String requesterIp,
      String xForwardedFor,
      String clientId,
      String scope,
      String grantType,
      boolean success
  ) {
    setNow(now);
    setCredentialName(credentialName);
    setOperation(operation);
    setUserId(userId);
    setUserName(userName);
    setUaaUrl(uaaUrl);
    setTokenIssued(tokenIssued);
    setTokenExpires(tokenExpires);
    setHostName(hostName);
    setMethod(method);
    setPath(path);
    setQueryParameters(queryParameters);
    setStatusCode(statusCode);
    setRequesterIp(requesterIp);
    setXForwardedFor(xForwardedFor);
    setClientId(clientId);
    setScope(scope);
    setGrantType(grantType);
    setSuccess(success);
  }

  public long getId() {
    return id;
  }

  public String getHostName() {
    return hostName;
  }

  public Instant getNow() {
    return now;
  }

  public String getOperation() {
    return operation;
  }

  public String getMethod() {
    return method;
  }

  public String getPath() {
    return path;
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public long getTokenIssued() {
    return tokenIssued;
  }

  public long getTokenExpires() {
    return tokenExpires;
  }

  public boolean isSuccess() {
    return success;
  }

  public String getUaaUrl() {
    return uaaUrl;
  }

  public String getUserId() {
    return userId;
  }

  public String getUserName() {
    return userName;
  }

  public String getRequesterIp() {
    return requesterIp;
  }

  public String getXForwardedFor() {
    return xForwardedFor;
  }

  public String getClientId() {
    return clientId;
  }

  public String getScope() {
    return scope;
  }

  public String getGrantType() {
    return grantType;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setRequesterIp(String requesterIp) {
    this.requesterIp = requesterIp;
  }

  public void setFailed() {
    this.success = false;
  }

  public void setOperation(String operation) {
    this.operation = operation;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public void setQueryParameters(String queryParameters) {
    this.queryParameters = queryParameters;
  }

  public void setXForwardedFor(String xForwardedFor) {
    this.xForwardedFor = xForwardedFor;
  }

  public void setId(long id) {
    this.id = id;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public void setScope(String scope) {
    this.scope = scope;
  }

  public void setGrantType(String grantType) {
    this.grantType = grantType;
  }

  public void setStatusCode(int statusCode) {
    this.statusCode = statusCode;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public void setNow(Instant now) {
    this.now = now;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public void setUaaUrl(String uaaUrl) {
    this.uaaUrl = uaaUrl;
  }

  public void setTokenIssued(long tokenIssued) {
    this.tokenIssued = tokenIssued;
  }

  public void setTokenExpires(long tokenExpires) {
    this.tokenExpires = tokenExpires;
  }

  public void setHostName(String hostName) {
    this.hostName = hostName;
  }

  public void setSuccess(boolean success) {
    this.success = success;
  }
}
