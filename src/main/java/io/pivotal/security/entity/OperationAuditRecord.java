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
    this.queryParameters = queryParameters;
    this.statusCode = statusCode;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.clientId = clientId;
    this.scope = scope;
    this.grantType = grantType;
    this.success = success;
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

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    OperationAuditRecord that = (OperationAuditRecord) o;

    if (id != that.id) return false;
    if (tokenIssued != that.tokenIssued) return false;
    if (tokenExpires != that.tokenExpires) return false;
    if (success != that.success) return false;
    if (statusCode != that.statusCode) return false;
    if (hostName != null ? !hostName.equals(that.hostName) : that.hostName != null) return false;
    if (now != null ? !now.equals(that.now) : that.now != null) return false;
    if (operation != null ? !operation.equals(that.operation) : that.operation != null) return false;
    if (path != null ? !path.equals(that.path) : that.path != null) return false;
    if (queryParameters != null ? !queryParameters.equals(that.queryParameters) : that.queryParameters != null)
      return false;
    if (uaaUrl != null ? !uaaUrl.equals(that.uaaUrl) : that.uaaUrl != null) return false;
    if (userId != null ? !userId.equals(that.userId) : that.userId != null) return false;
    if (userName != null ? !userName.equals(that.userName) : that.userName != null) return false;
    if (requesterIp != null ? !requesterIp.equals(that.requesterIp) : that.requesterIp != null) return false;
    if (xForwardedFor != null ? !xForwardedFor.equals(that.xForwardedFor) : that.xForwardedFor != null) return false;
    if (clientId != null ? !clientId.equals(that.clientId) : that.clientId != null) return false;
    if (scope != null ? !scope.equals(that.scope) : that.scope != null) return false;
    if (grantType != null ? !grantType.equals(that.grantType) : that.grantType != null) return false;
    return method != null ? method.equals(that.method) : that.method == null;

  }

  @Override
  public int hashCode() {
    int result = (int) (id ^ (id >>> 32));
    result = 31 * result + (hostName != null ? hostName.hashCode() : 0);
    result = 31 * result + (now != null ? now.hashCode() : 0);
    result = 31 * result + (operation != null ? operation.hashCode() : 0);
    result = 31 * result + (path != null ? path.hashCode() : 0);
    result = 31 * result + (queryParameters != null ? queryParameters.hashCode() : 0);
    result = 31 * result + (int) (tokenIssued ^ (tokenIssued >>> 32));
    result = 31 * result + (int) (tokenExpires ^ (tokenExpires >>> 32));
    result = 31 * result + (success ? 1 : 0);
    result = 31 * result + (uaaUrl != null ? uaaUrl.hashCode() : 0);
    result = 31 * result + (userId != null ? userId.hashCode() : 0);
    result = 31 * result + (userName != null ? userName.hashCode() : 0);
    result = 31 * result + (requesterIp != null ? requesterIp.hashCode() : 0);
    result = 31 * result + (xForwardedFor != null ? xForwardedFor.hashCode() : 0);
    result = 31 * result + (clientId != null ? clientId.hashCode() : 0);
    result = 31 * result + (scope != null ? scope.hashCode() : 0);
    result = 31 * result + (grantType != null ? grantType.hashCode() : 0);
    result = 31 * result + (method != null ? method.hashCode() : 0);
    result = 31 * result + statusCode;
    return result;
  }
}
