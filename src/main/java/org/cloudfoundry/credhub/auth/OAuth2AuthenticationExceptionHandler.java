package org.cloudfoundry.credhub.auth;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

import org.cloudfoundry.credhub.exceptions.AccessTokenExpiredException;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;

import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.EXP;

@Service
@ConditionalOnProperty("security.oauth2.enabled")
public class OAuth2AuthenticationExceptionHandler extends OAuth2AuthenticationEntryPoint {

  private final CurrentTimeProvider currentTimeProvider;
  private final JsonParser objectMapper;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  OAuth2AuthenticationExceptionHandler(
    final CurrentTimeProvider currentTimeProvider,
    final MessageSourceAccessor messageSourceAccessor
  ) {
    super();
    this.currentTimeProvider = currentTimeProvider;
    this.objectMapper = JsonParserFactory.create();
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @Override
  public void commence(
    final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException)
    throws IOException, ServletException {
    handleException(request, response, authException);
  }


  public void handleException(final HttpServletRequest request, final HttpServletResponse response,
                              final RuntimeException runtimeException)
    throws IOException, ServletException {

    final String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);

    final Map<String, Object> tokenInformation = extractTokenInformation(token);

    final Throwable cause = extractCause(runtimeException);

    final Exception exception;
    if (tokenIsExpired(tokenInformation)) {
      exception = new AccessTokenExpiredException("Access token expired", cause);
    } else if (cause instanceof InvalidSignatureException) {
      exception = new OAuthSignatureException(
        removeTokenFromMessage(messageSourceAccessor.getMessage("error.invalid_token_signature"), token));
    } else if (cause instanceof SignatureException) {
      exception = new OAuthSignatureException(
        removeTokenFromMessage(messageSourceAccessor.getMessage("error.malformed_token"), token));
    } else {
      exception = new InvalidTokenException(
        removeTokenFromMessage(runtimeException.getMessage(), token), cause);
    }

    exception.setStackTrace(runtimeException.getStackTrace());

    doHandle(request, response, exception);
  }

  private Throwable extractCause(final RuntimeException e) {
    Throwable cause = e.getCause();
    Throwable nextCause = cause == null ? null : cause.getCause();
    while (nextCause != null && !(nextCause.equals(cause))) {
      cause = nextCause;
      nextCause = cause.getCause();
    }
    return cause;
  }

  private boolean tokenIsExpired(final Map<String, Object> tokenInformation) {
    final Long exp = tokenInformation != null ? (Long) tokenInformation.get(EXP) : null;
    return exp != null && exp <= currentTimeProvider.getInstant().getEpochSecond();
  }

  private Map<String, Object> extractTokenInformation(final String token) {
    try {
      final Jwt jwt = JwtHelper.decode(token);

      final Map<String, Object> map = objectMapper.parseMap(jwt.getClaims());
      if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
        final Integer intValue = (Integer) map.get(EXP);
        map.put(EXP, Long.valueOf(intValue));
      }

      return map;
    } catch (final RuntimeException mie) {
      return null;
    }
  }

  private String removeTokenFromMessage(final String message, final String token) {
    return message.replace(": " + token, "");
  }
}


