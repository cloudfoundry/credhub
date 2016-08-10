package io.pivotal.security.oauth;

import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.repository.AuthFailureAuditRecordRepository;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.InstantFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Service;

import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.EXP;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
public class AuditOAuth2AuthenticationEntryPoint extends OAuth2AuthenticationEntryPoint {

  @Autowired
  private InstantFactoryBean instantFactoryBean;

  @Autowired
  AuthFailureAuditRecordRepository auditRecordRepository;

  @Autowired
  JwtAccessTokenConverter jwtAccessTokenConverter;

  private JsonParser objectMapper = JsonParserFactory.create();

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {

    final OAuth2AccessToken oAuth2AccessToken = extractAuthentication(request);
    logAuthFailureToDb(oAuth2AccessToken, authException, new AuditRecordParameters(request, null), request.getMethod());
    doHandle(request, response, authException);
  }

  private OAuth2AccessToken extractAuthentication(HttpServletRequest request) {
    String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);
    try {
      final Jwt jwt = JwtHelper.decode(token);

      final Map<String, Object> map = objectMapper.parseMap(jwt.getClaims());
      if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
        Integer intValue = (Integer) map.get(EXP);
        map.put(EXP, new Long(intValue));
      }

      return jwtAccessTokenConverter.extractAccessToken(token, map);
    } catch (RuntimeException mie) {
      return null;
    }
  }

  private void logAuthFailureToDb(OAuth2AccessToken oAuth2AccessToken, AuthenticationException authException, AuditRecordParameters parameters, String requestMethod) {
    RequestToOperationTranslator requestToOperationTranslator = new RequestToOperationTranslator(parameters.getPath()).setMethod(requestMethod);

    final Instant now;
    try {
      now = instantFactoryBean.getObject();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    String userId = null;
    String userName = null;
    String iss = null;
    long issued = -1;
    long expires = -1;

    if (oAuth2AccessToken != null) {
      Map<String, Object> additionalInformation = oAuth2AccessToken.getAdditionalInformation();
      userId = (String) additionalInformation.get("user_id");
      userName = (String) additionalInformation.get("user_name");
      iss = (String) additionalInformation.get("iss");
      issued = ((Number) additionalInformation.get("iat")).longValue();
      expires = oAuth2AccessToken.getExpiration().toInstant().getEpochSecond();
    }

    AuthFailureAuditRecord authFailureAuditRecord = new AuthFailureAuditRecord()
        .setNow(now)
        .setOperation(requestToOperationTranslator.translate())
        .setFailureDescription(authException.getMessage())
        .setUserId(userId)
        .setUserName(userName)
        .setUaaUrl(iss)
        .setTokenIssued(issued)
        .setTokenExpires(expires)
        .setHostName(parameters.getHostName())
        .setPath(parameters.getPath())
        .setRequesterIp(parameters.getRequesterIp())
        .setXForwardedFor(parameters.getXForwardedFor());
    auditRecordRepository.save(authFailureAuditRecord);
  }
}


