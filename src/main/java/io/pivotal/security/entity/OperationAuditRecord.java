package io.pivotal.security.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@SuppressWarnings("unused")
@Entity
@Table(name = "OperationAuditRecord")
@EntityListeners(AuditingEntityListener.class)
public class OperationAuditRecord {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  private String hostName;
  private long now;
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

  public OperationAuditRecord() {
  }

  public OperationAuditRecord(long now,
                              String operation,
                              String userId,
                              String userName,
                              String uaaUrl,
                              long tokenIssued,
                              long tokenExpires,
                              String hostName,
                              String path,
                              String requesterIp,
                              String xForwardedFor) {
    this.now = now;
    this.operation = operation;
    this.userId = userId;
    this.userName = userName;
    this.uaaUrl = uaaUrl;
    this.tokenIssued = tokenIssued;
    this.tokenExpires = tokenExpires;
    this.hostName = hostName;
    this.path = path;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
  }

  public long getId() {
    return id;
  }

  public String getHostName() {
    return hostName;
  }

  public long getNow() {
    return now;
  }

  public String getOperation() {
    return operation;
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

  public void setRequesterIp(String requesterIp) {
    this.requesterIp = requesterIp;
  }

  public void setFailed() {
    this.success = false;
  }

  public void setOperation(String operation) {
    this.operation = operation;
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
}
