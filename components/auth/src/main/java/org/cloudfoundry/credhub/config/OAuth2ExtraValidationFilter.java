package org.cloudfoundry.credhub.config;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.auth.OAuth2AuthenticationExceptionHandler;
import org.cloudfoundry.credhub.auth.OAuth2IssuerService;

@Service
@ConditionalOnProperty("security.oauth2.enabled")
public class OAuth2ExtraValidationFilter extends OncePerRequestFilter {

  private final TokenStore tokenStore;
  private final OAuth2AuthenticationExceptionHandler oAuth2AuthenticationExceptionHandler;
  private final AuthenticationEventPublisher eventPublisher;
  private final TokenExtractor tokenExtractor;
  private final OAuth2IssuerService oAuth2IssuerService;

  @Autowired
  OAuth2ExtraValidationFilter(
    final OAuth2IssuerService oAuth2IssuerService,
    final TokenStore tokenStore,
    final OAuth2AuthenticationExceptionHandler oAuth2AuthenticationExceptionHandler,
    final AuthenticationEventPublisher eventPublisher
  ) {
    super();
    this.oAuth2IssuerService = oAuth2IssuerService;
    this.tokenStore = tokenStore;
    this.oAuth2AuthenticationExceptionHandler = oAuth2AuthenticationExceptionHandler;
    this.eventPublisher = eventPublisher;
    this.tokenExtractor = new BearerTokenExtractor();
  }

  @Override
  protected void doFilterInternal(
    final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
    throws ServletException, IOException {
    final Authentication authentication = tokenExtractor.extract(request);

    try {
      if (authentication != null) {
        final String token = (String) authentication.getPrincipal();
        final OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);
        final Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
        final String issuer = (String) additionalInformation.getOrDefault("iss", "");

        if (!issuer.equals(oAuth2IssuerService.getIssuer())) {
          tokenStore.removeAccessToken(accessToken);

          final String errorMessage = ErrorMessages.Oauth.INVALID_ISSUER;
          throw new OAuth2Exception(errorMessage);
          //        AuthenticationServiceException authException = new AuthenticationServiceException(errorMessage);
          //        oAuth2AuthenticationExceptionHandler.commence(request, response, authException);
        }

      }

      filterChain.doFilter(request, response);
    } catch (final OAuth2Exception exception) {
      SecurityContextHolder.clearContext();
      final InsufficientAuthenticationException authException = new InsufficientAuthenticationException(
        exception.getMessage(), exception);
      eventPublisher.publishAuthenticationFailure(new BadCredentialsException(exception.getMessage(), exception),
        new PreAuthenticatedAuthenticationToken("access-token", "N/A"));
      oAuth2AuthenticationExceptionHandler.handleException(request, response, authException);
    } catch (final RuntimeException exception) {
      if (exception.getCause() instanceof SignatureException || exception
        .getCause() instanceof InvalidSignatureException) {
        oAuth2AuthenticationExceptionHandler.handleException(request, response, exception);
      } else {
        throw exception;
      }
    }
  }
}
