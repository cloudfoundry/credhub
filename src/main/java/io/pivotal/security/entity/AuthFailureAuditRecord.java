package io.pivotal.security.entity;

import io.pivotal.security.util.InstantMillisecondsConverter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;

@SuppressWarnings("unused")
@Entity
@Table(name = "AuthFailureAuditRecord")
@EntityListeners(AuditingEntityListener.class)
public class AuthFailureAuditRecord {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  private String hostName;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  private Instant now;

  private String operation;
  private String path;

  private long authValidFrom;
  private long authValidUntil;

  @Column(length = 2000)
  private String failureDescription;

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
  private String queryParameters;

  public AuthFailureAuditRecord() {
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

  public String getFailureDescription() {
    return failureDescription;
  }

  public String getPath() {
    return path;
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public long getAuthValidFrom() {
    return authValidFrom;
  }

  public long getAuthValidUntil() {
    return authValidUntil;
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

  public String getMethod() {
    return method;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public AuthFailureAuditRecord setNow(Instant now) {
    this.now = now;
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

  public AuthFailureAuditRecord setAuthValidFrom(long authValidFrom) {
    this.authValidFrom = authValidFrom;
    return this;
  }

  public AuthFailureAuditRecord setAuthValidUntil(long authValidUntil) {
    this.authValidUntil = authValidUntil;
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

  public AuthFailureAuditRecord setQueryParameters(String queryParameters) {
    this.queryParameters = queryParameters;
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

  public AuthFailureAuditRecord setClientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public AuthFailureAuditRecord setScope(String scope) {
    this.scope = scope;
    return this;
  }

  public AuthFailureAuditRecord setGrantType(String grantType) {
    this.grantType = grantType;
    return this;
  }

  public AuthFailureAuditRecord setMethod(String method) {
    this.method = method;
    return this;
  }

  public AuthFailureAuditRecord setStatusCode(int statusCode) {
    this.statusCode = statusCode;
    return this;
  }
}
