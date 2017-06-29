package io.pivotal.security.config;

import io.pivotal.security.auth.AuditOAuth2AuthenticationExceptionHandler;
import io.pivotal.security.auth.OAuth2IssuerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class OAuth2ExtraValidationFilter extends OncePerRequestFilter {

  private final MessageSourceAccessor messageSourceAccessor;
  private TokenStore tokenStore;
  private AuditOAuth2AuthenticationExceptionHandler oAuth2AuthenticationExceptionHandler;
  private TokenExtractor tokenExtractor;
  private OAuth2IssuerService oAuth2IssuerService;

  @Autowired
  OAuth2ExtraValidationFilter(
      OAuth2IssuerService oAuth2IssuerService,
      TokenStore tokenStore,
      AuditOAuth2AuthenticationExceptionHandler oAuth2AuthenticationExceptionHandler,
      MessageSource messageSource
  ) {
    this.oAuth2IssuerService = oAuth2IssuerService;
    this.tokenStore = tokenStore;
    this.oAuth2AuthenticationExceptionHandler = oAuth2AuthenticationExceptionHandler;
    this.tokenExtractor = new BearerTokenExtractor();
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    Authentication authentication = tokenExtractor.extract(request);

    if (authentication != null) {
      String token = (String) authentication.getPrincipal();
      OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);
      Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
      String issuer = (String) additionalInformation.getOrDefault("iss", "");

      if (!issuer.equals(oAuth2IssuerService.getIssuer())) {
        tokenStore.removeAccessToken(accessToken);

        String errorMessage = messageSourceAccessor.getMessage("error.oauth.invalid_issuer");
        oAuth2AuthenticationExceptionHandler.commence(request, response, new AuthenticationServiceException(errorMessage));
      }
    }

    filterChain.doFilter(request, response);
  }
}
