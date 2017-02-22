package io.pivotal.security.config;

import io.pivotal.security.oauth.AuditOAuth2AccessDeniedHandler;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class OAuth2Configuration {
  @Bean
  public ResourceServerProperties resourceServerProperties() {
    return new ResourceServerProperties();
  }

  @Bean
  public DefaultAccessTokenConverter defaultAccessTokenConverter() {
    DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
    defaultAccessTokenConverter.setIncludeGrantType(true);
    return defaultAccessTokenConverter;
  }

  @Bean
  public JwtAccessTokenConverter jwtAccessTokenConverter(DefaultAccessTokenConverter defaultAccessTokenConverter) throws Exception {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter);
    jwtAccessTokenConverter.setVerifierKey(resourceServerProperties().getJwt().getKeyValue());
    jwtAccessTokenConverter.afterPropertiesSet();
    return jwtAccessTokenConverter;
  }

  @Bean
  public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
    return new JwtTokenStore(jwtAccessTokenConverter);
  }

  @Bean
  public ResourceServerTokenServices resourceServerTokenServices(TokenStore tokenStore) {
    DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
    defaultTokenServices.setTokenStore(tokenStore);
    return defaultTokenServices;
  }

  @Bean
  public AuditOAuth2AccessDeniedHandler getAuditOAuth2AccessDeniedHandler() {
    return new AuditOAuth2AccessDeniedHandler();
  }

  @Bean
  public AuthenticationManagerBuilder authenticationManagerBuilder() {
    final AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder(new ObjectPostProcessor<Object>() {
      @Override
      public <O extends Object> O postProcess(O object) {
        return object;
      }
    });
    authenticationManagerBuilder.parentAuthenticationManager(authenticationManager());
    return authenticationManagerBuilder;
  }

  @Bean
  public AuthenticationManager authenticationManager() {
    return new AuthenticationManager() {
      @Override
      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication;
      }
    };
  }
}
