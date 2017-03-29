package io.pivotal.security.entity;

import io.pivotal.security.util.InstantMillisecondsConverter;
import java.time.Instant;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

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
  private long authValidFrom;
  private long authValidUntil;
  private boolean success = true;
  private String uaaUrl;
  private String userId;
  private String userName;
  private String requesterIp;
  @SuppressWarnings("checkstyle:membername")
  private String xForwardedFor;
  private String clientId;
  private String scope;
  private String grantType;
  private String method;
  private int statusCode;
  private String authMethod;

  public OperationAuditRecord() {
  }

  @SuppressWarnings("checkstyle:parametername")
  public OperationAuditRecord(
      String authMethod,
      Instant now,
      String credentialName,
      String operation,
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
      String grantType,
      boolean success
  ) {
    this.authMethod = authMethod;
    this.now = now;
    this.credentialName = credentialName;
    this.operation = operation;
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
    this.success = success;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
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

  public long getAuthValidFrom() {
    return authValidFrom;
  }

  public long getAuthValidUntil() {
    return authValidUntil;
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

}
