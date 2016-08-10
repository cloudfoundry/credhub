package io.pivotal.security.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@SuppressWarnings("unused")
@Entity
@Table(name = "AuthFailureAuditRecord")
@EntityListeners(AuditingEntityListener.class)
public class AuthFailureAuditRecord {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  private String hostName;

  @Temporal(TemporalType.TIMESTAMP)
  private Date now;

  private String operation;
  private String path;
  private long tokenIssued;
  private long tokenExpires;

  @Column(length = 2000)
  private String failureDescription;

  private String uaaUrl;
  private String userId;
  private String userName;
  private String requesterIp;
  private String xForwardedFor;

  public AuthFailureAuditRecord() {
  }

  public AuthFailureAuditRecord(Instant now,
                                String operation,
                                String failureDescription,
                                String errorMessage,
                                String userId,
                                String userName,
                                String uaaUrl,
                                long tokenIssued,
                                long tokenExpires,
                                String hostName,
                                String path,
                                String requesterIp,
                                String xForwardedFor) {
    this.now = Date.from(now);
    this.operation = operation;
    this.failureDescription = failureDescription;
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

  public Instant getNow() {
    return now.toInstant();
  }

  public String getOperation() {
    return operation;
  }

  public String getFailureDescription() {
    return failureDescription;
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

  public AuthFailureAuditRecord setNow(Instant now) {
    this.now = Date.from(now);
    return this;
  }

  public AuthFailureAuditRecord setRequesterIp(String requesterIp) {
    this.requesterIp = requesterIp;
    return this;
  }

  public AuthFailureAuditRecord setFailureDescription(String failureDescription) {
    this.failureDescription = failureDescription;
    return this;
  }

  public AuthFailureAuditRecord setUserId(String userId) {
    this.userId = userId;
    return this;
  }

  public AuthFailureAuditRecord setTokenIssued(long tokenIssued) {
    this.tokenIssued = tokenIssued;
    return this;
  }

  public AuthFailureAuditRecord setTokenExpires(long tokenExpires) {
    this.tokenExpires = tokenExpires;
    return this;
  }

  public AuthFailureAuditRecord setUaaUrl(String uaaUrl) {
    this.uaaUrl = uaaUrl;
    return this;
  }

  public AuthFailureAuditRecord setUserName(String userName) {
    this.userName = userName;
    return this;
  }

  public AuthFailureAuditRecord setOperation(String operation) {
    this.operation = operation;
    return this;
  }

  public AuthFailureAuditRecord setPath(String path) {
    this.path = path;
    return this;
  }

  public AuthFailureAuditRecord setXForwardedFor(String xForwardedFor) {
    this.xForwardedFor = xForwardedFor;
    return this;
  }

  public AuthFailureAuditRecord setHostName(String hostName) {
    this.hostName = hostName;
    return this;
  }

  public AuthFailureAuditRecord setId(long id) {
    this.id = id;
    return this;
  }
}
