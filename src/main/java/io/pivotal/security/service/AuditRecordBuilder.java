package io.pivotal.security.service;

import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.OperationAuditRecord;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

import static io.pivotal.security.entity.AuditingOperationCode.*;

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
  private OAuth2Authentication authentication;
  private boolean isSuccess;

  public AuditRecordBuilder(String credentialName,
                            HttpServletRequest request,
                            Authentication authentication) {
    this(
        request.getServerName(),
        credentialName,
        request.getMethod(),
        request.getRequestURI(),
        request.getQueryString(),
        request.getRemoteAddr(),
        extractXForwardedFor(request.getHeaders("X-Forwarded-For")),
        authentication
    );
  }

  AuditRecordBuilder(String hostName,
                     String credentialName,
                     String method,
                     String path,
                     String queryParameters,
                     String requesterIp,
                     String xForwardedFor,
                     Authentication authentication) {
    this.hostName = hostName;
    this.credentialName = credentialName;
    this.method = method;
    this.path = path;
    this.queryParameters = queryParameters;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.authentication = (OAuth2Authentication) authentication;
    this.operationCode = computeOperationCode();
  }

  public AuditRecordBuilder(AuditingOperationCode operationCode, String secretName, HttpServletRequest request, Authentication authentication) {
    this(secretName, request, authentication);
    this.operationCode = operationCode;
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

  public Authentication getAuthentication() {
    return authentication;
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

  public OperationAuditRecord build(Instant now) {
    OAuth2Request oAuth2Request = authentication.getOAuth2Request();

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
        claimValueAsLong(accessToken.getAdditionalInformation(),"iat"),
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
  }

  /*
   * The "iat" and "exp" claims are parsed by Jackson as integers. That means we have a
   * Year-2038 bug. In the hope that Jackson will someday be fixed, this function returns
   * a numeric value as long.
   */
  private long claimValueAsLong(Map<String, Object> additionalInformation, String claimName) {
    return ((Number) additionalInformation.get(claimName)).longValue();
  }

  public AuditRecordBuilder computeAccessToken(ResourceServerTokenServices tokenServices) {
    OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
    setAccessToken(tokenServices.readAccessToken(authenticationDetails.getTokenValue()));

    return this;
  }
}
