package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.util.InstantMillisecondsConverter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.Id;
import javax.persistence.Table;

import static org.cloudfoundry.credhub.constants.UuidConstants.UUID_BYTES;

@SuppressWarnings("unused")
@Entity
@Table(name = "request_audit_record")
@EntityListeners(AuditingEntityListener.class)
public class RequestAuditRecord {

  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID uuid;

  private String hostName;
  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  private Instant now;

  private String path;
  private String queryParameters;
  private long authValidFrom;
  private long authValidUntil;
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
  private String authMethod;

  public RequestAuditRecord() {
  }

  public RequestAuditRecord(
      UUID uuid,
      Instant now,
      String authMethod,
      String userId,
      String userName,
      String uaaUrl,
      long authValidFrom,
      long authValidUntil,
      String hostName,
      String method,
      String path,
      String queryParameters,
      int statusCode,
      String requesterIp,
      String xForwardedFor,
      String clientId,
      String scope,
      String grantType
  ) {
    this.uuid = uuid;
    this.now = now;
    this.authMethod = authMethod;
    this.userId = userId;
    this.userName = userName;
    this.uaaUrl = uaaUrl;
    this.authValidFrom = authValidFrom;
    this.authValidUntil = authValidUntil;
    this.hostName = hostName;
    this.method = method;
    this.path = path;
    this.queryParameters = queryParameters;
    this.statusCode = statusCode;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.clientId = clientId;
    this.scope = scope;
    this.grantType = grantType;
  }

  public UUID getUuid() {
    return uuid;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public String getHostName() {
    return hostName;
  }

  public Instant getNow() {
    return now;
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

  public int getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(int statusCode) {
    this.statusCode = statusCode;
  }
}
