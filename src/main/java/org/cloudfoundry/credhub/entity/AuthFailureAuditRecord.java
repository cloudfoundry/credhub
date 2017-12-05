package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.util.InstantMillisecondsConverter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@SuppressWarnings("unused")
@Entity
@Table(name = "auth_failure_audit_record")
@EntityListeners(AuditingEntityListener.class)
public class AuthFailureAuditRecord {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  private String hostName;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  private Instant now;

  private String path;

  private long authValidFrom;
  private long authValidUntil;
  private String authMethod;

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

  public AuthFailureAuditRecord setId(long id) {
    this.id = id;
    return this;
  }

  public String getHostName() {
    return hostName;
  }

  public AuthFailureAuditRecord setHostName(String hostName) {
    this.hostName = hostName;
    return this;
  }

  public Instant getNow() {
    return now;
  }

  public AuthFailureAuditRecord setNow(Instant now) {
    this.now = now;
    return this;
  }

  public String getFailureDescription() {
    return failureDescription;
  }

  public AuthFailureAuditRecord setFailureDescription(String failureDescription) {
    this.failureDescription = failureDescription;
    return this;
  }

  public String getPath() {
    return path;
  }

  public AuthFailureAuditRecord setPath(String path) {
    this.path = path;
    return this;
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public AuthFailureAuditRecord setQueryParameters(String queryParameters) {
    this.queryParameters = queryParameters;
    return this;
  }

  public long getAuthValidFrom() {
    return authValidFrom;
  }

  public AuthFailureAuditRecord setAuthValidFrom(long authValidFrom) {
    this.authValidFrom = authValidFrom;
    return this;
  }

  public long getAuthValidUntil() {
    return authValidUntil;
  }

  public AuthFailureAuditRecord setAuthValidUntil(long authValidUntil) {
    this.authValidUntil = authValidUntil;
    return this;
  }

  public String getUaaUrl() {
    return uaaUrl;
  }

  public AuthFailureAuditRecord setUaaUrl(String uaaUrl) {
    this.uaaUrl = uaaUrl;
    return this;
  }

  public String getUserId() {
    return userId;
  }

  public AuthFailureAuditRecord setUserId(String userId) {
    this.userId = userId;
    return this;
  }

  public String getUserName() {
    return userName;
  }

  public AuthFailureAuditRecord setUserName(String userName) {
    this.userName = userName;
    return this;
  }

  public String getRequesterIp() {
    return requesterIp;
  }

  public AuthFailureAuditRecord setRequesterIp(String requesterIp) {
    this.requesterIp = requesterIp;
    return this;
  }

  public String getXForwardedFor() {
    return xForwardedFor;
  }

  public AuthFailureAuditRecord setXForwardedFor(String xForwardedFor) {
    this.xForwardedFor = xForwardedFor;
    return this;
  }

  public String getClientId() {
    return clientId;
  }

  public AuthFailureAuditRecord setClientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public String getScope() {
    return scope;
  }

  public AuthFailureAuditRecord setScope(String scope) {
    this.scope = scope;
    return this;
  }

  public String getGrantType() {
    return grantType;
  }

  public AuthFailureAuditRecord setGrantType(String grantType) {
    this.grantType = grantType;
    return this;
  }

  public String getMethod() {
    return method;
  }

  public AuthFailureAuditRecord setMethod(String method) {
    this.method = method;
    return this;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public AuthFailureAuditRecord setStatusCode(int statusCode) {
    this.statusCode = statusCode;
    return this;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public AuthFailureAuditRecord setAuthMethod(String authMethod) {
    this.authMethod = authMethod;
    return this;
  }
}
