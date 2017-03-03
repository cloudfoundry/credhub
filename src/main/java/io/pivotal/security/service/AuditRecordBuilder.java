package io.pivotal.security.service;

import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.OperationAuditRecord;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.UNKNOWN_OPERATION;

import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

public class AuditRecordBuilder {
  private final String hostName;
  private final String method;
  private final String path;
  private final String requesterIp;
  private final String xForwardedFor;
  private final String queryParameters;
  private String credentialName;
  private AuditingOperationCode operationCode;
  private int requestStatus;
  private OAuth2AccessToken accessToken;
  private Authentication authentication;
  private boolean isSuccess;

  public AuditRecordBuilder(String credentialName,
                            HttpServletRequest request,
                            Authentication authentication) {
    this.credentialName = credentialName;
    this.hostName = request.getServerName();
    this.method = request.getMethod();
    this.path = request.getRequestURI();
    this.queryParameters = request.getQueryString();
    this.requesterIp = request.getRemoteAddr();
    this.xForwardedFor = extractXForwardedFor(request.getHeaders("X-Forwarded-For"));
    this.authentication = authentication;
    this.operationCode = computeOperationCode();
  }

  public AuditingOperationCode getOperationCode() {
    return operationCode;
  }

  public String getHostName() {
    return hostName;
  }

  public String getMethod() {
    return method;
  }

  public String getPath() {
    return path;
  }

  public String getRequesterIp() {
    return requesterIp;
  }

  public String getXForwardedFor() {
    return xForwardedFor;
  }

  private static String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public AuditRecordBuilder setCredentialName(String credentialName) {
    this.credentialName = credentialName;
    return this;
  }

  public String getCredentialName() {
    return credentialName;
  }

  private AuditingOperationCode computeOperationCode() {
    switch (method) {
      case "GET":
        return CREDENTIAL_ACCESS;
      case "POST":
      case "PUT":
        return CREDENTIAL_UPDATE;
      case "DELETE":
        return CREDENTIAL_DELETE;
      default:
        return UNKNOWN_OPERATION;
    }
  }

  public AuditRecordBuilder setRequestStatus(int requestStatus) {
    this.requestStatus = requestStatus;
    return this;
  }

  public AuditRecordBuilder setAuthentication(OAuth2Authentication authentication) {
    this.authentication = authentication;
    return this;
  }

  public AuditRecordBuilder setAccessToken(OAuth2AccessToken accessToken) {
    this.accessToken = accessToken;
    return this;
  }

  public AuditRecordBuilder setIsSuccess(boolean isSuccess) {
    this.isSuccess = isSuccess;
    return this;
  }

  public AuditRecordBuilder setOperationCode(AuditingOperationCode operationCode) {
    this.operationCode = operationCode;
    return this;
  }

  public OperationAuditRecord build(Instant now) {
    if (authentication instanceof OAuth2Authentication) {
      OAuth2Request oAuth2Request = ((OAuth2Authentication) authentication).getOAuth2Request();

      String path = getPath();
      String method = getMethod();

      Set<String> scopes = accessToken.getScope();
      String scope = scopes == null ? null : String.join(",", scopes);

      return new OperationAuditRecord(
        now,
        getCredentialName(),
        getOperationCode().toString(),
        (String) accessToken.getAdditionalInformation().get("user_id"),
        (String) accessToken.getAdditionalInformation().get("user_name"),
        (String) accessToken.getAdditionalInformation().get("iss"),
        claimValueAsLong(accessToken.getAdditionalInformation(), "iat"),
        accessToken.getExpiration().toInstant().getEpochSecond(), // accessToken.getExpiration().getTime() / 1000,?
        getHostName(),
        method,
        path,
        getQueryParameters(),
        requestStatus,
        getRequesterIp(),
        getXForwardedFor(),
        oAuth2Request.getClientId(),
        scope,
        oAuth2Request.getGrantType(),
        isSuccess
      );
    } else {
      return new OperationAuditRecord(
        now,
        getCredentialName(),
        getOperationCode().toString(),
        "MTLS",
        "MTLS",
        "MTLS",
        0,
        0,
        getHostName(),
        method,
        path,
        getQueryParameters(),
        requestStatus,
        getRequesterIp(),
        getXForwardedFor(),
        "MTLS",
        "MTLS",
        "MTLS",
        isSuccess
      );
    }
  }

  /*
   * The "iat" and "exp" claims are parsed by Jackson as integers. That means we have a
   * Year-2038 bug. In the hope that Jackson will someday be fixed, this function returns
   * a numeric value as long.
   */
  private long claimValueAsLong(Map<String, Object> additionalInformation, String claimName) {
    return ((Number) additionalInformation.get(claimName)).longValue();
  }

  AuditRecordBuilder computeAccessToken(ResourceServerTokenServices tokenServices) {
    if (authentication instanceof OAuth2Authentication) {
      OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
      setAccessToken(tokenServices.readAccessToken(authenticationDetails.getTokenValue()));
    }

    return this;
  }
}
