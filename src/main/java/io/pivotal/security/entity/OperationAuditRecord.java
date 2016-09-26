package io.pivotal.security.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

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
  private String operation;
  private String path;
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

  public OperationAuditRecord(Instant now,
                              String operation,
                              String userId,
                              String userName,
                              String uaaUrl,
                              long tokenIssued,
                              long tokenExpires,
                              String hostName,
                              String method,
                              String path,
                              String requesterIp,
                              String xForwardedFor,
                              String clientId,
                              String scope,
                              String grantType) {
    this.now = now;
    this.operation = operation;
    this.userId = userId;
    this.userName = userName;
    this.uaaUrl = uaaUrl;
    this.tokenIssued = tokenIssued;
    this.tokenExpires = tokenExpires;
    this.hostName = hostName;
    this.method = method;
    this.path = path;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.clientId = clientId;
    this.scope = scope;
    this.grantType = grantType;
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
}
