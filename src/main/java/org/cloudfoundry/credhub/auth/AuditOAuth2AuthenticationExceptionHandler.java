package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.audit.AuditLogFactory;
import org.cloudfoundry.credhub.data.AuthFailureAuditRecordDataService;
import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.cloudfoundry.credhub.exceptions.AccessTokenExpiredException;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.EXP;

@Service
@ConditionalOnProperty(value = "security.oauth2.enabled")
public class AuditOAuth2AuthenticationExceptionHandler extends OAuth2AuthenticationEntryPoint {

  private final CurrentTimeProvider currentTimeProvider;
  private final AuthFailureAuditRecordDataService authFailureAuditRecordDataService;
  private final AuditLogFactory auditLogFactory;
  private final JsonParser objectMapper;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  AuditOAuth2AuthenticationExceptionHandler(
      CurrentTimeProvider currentTimeProvider,
      AuthFailureAuditRecordDataService authFailureAuditRecordDataService,
      MessageSourceAccessor messageSourceAccessor,
      AuditLogFactory auditLogFactory
  ) {
    this.currentTimeProvider = currentTimeProvider;
    this.authFailureAuditRecordDataService = authFailureAuditRecordDataService;
    this.auditLogFactory = auditLogFactory;
    this.objectMapper = JsonParserFactory.create();
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {

    String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);

    final Map<String, Object> tokenInformation = extractTokenInformation(token);

    Throwable cause = extractCause(authException);

    Exception exception;
    if (tokenIsExpired(tokenInformation)) {
      exception = new AccessTokenExpiredException("Access token expired", cause);
    } else if (cause instanceof InvalidSignatureException || cause instanceof SignatureException) {
      exception = new InvalidTokenException(
          messageSourceAccessor.getMessage("error.invalid_token_signature"), cause);
    } else {
      exception = new InvalidTokenException(
          removeTokenFromMessage(authException.getMessage(), token), cause);
    }
    exception.setStackTrace(authException.getStackTrace());

    try {
      doHandle(request, response, exception);
    } finally {
      final String message = removeTokenFromMessage(exception.getMessage(), token);
      logAuthFailureToDb(request, tokenInformation, response.getStatus(), message);
    }
  }

  private Throwable extractCause(AuthenticationException e) {
    Throwable cause = e.getCause();
    Throwable nextCause = cause == null ? null : cause.getCause();
    while (nextCause != null && nextCause != cause) {
      cause = nextCause;
      nextCause = cause.getCause();
    }
    return cause;
  }

  private boolean tokenIsExpired(Map<String, Object> tokenInformation) {
    Long exp = tokenInformation != null ? (Long) tokenInformation.get(EXP) : null;
    return exp != null && exp <= currentTimeProvider.getNow().getTimeInMillis() / 1000;
  }

  private Map<String, Object> extractTokenInformation(String token) {
    try {
      final Jwt jwt = JwtHelper.decode(token);

      final Map<String, Object> map = objectMapper.parseMap(jwt.getClaims());
      if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
        Integer intValue = (Integer) map.get(EXP);
        map.put(EXP, Long.valueOf(intValue));
      }

      return map;
    } catch (RuntimeException mie) {
      return null;
    }
  }

  private void logAuthFailureToDb(
      HttpServletRequest request,
      Map<String, Object> tokenInformation,
      int statusCode,
      String message
  ) {
    AuthFailureAuditRecord authFailureAuditRecord = auditLogFactory.createAuthFailureAuditRecord(
        request,
        tokenInformation,
        statusCode,
        message
    );
    authFailureAuditRecordDataService.save(authFailureAuditRecord);
  }

  private String removeTokenFromMessage(String message, String token) {
    return message.replace(": " + token, "");
  }
}


