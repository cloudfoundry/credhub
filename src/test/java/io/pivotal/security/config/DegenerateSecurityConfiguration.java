package io.pivotal.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class DegenerateSecurityConfiguration {

  @Bean
  ResourceServerTokenServices tokenServices() throws Exception {
    return new SelfValidatingResourceTokenServices();
  }

  static class SelfValidatingResourceTokenServices implements ResourceServerTokenServices {

    private final JwtTokenStore jwtTokenStore;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    SelfValidatingResourceTokenServices() throws Exception {
      jwtAccessTokenConverter = new JwtAccessTokenConverter();
      jwtAccessTokenConverter.setSigningKey("tokenkey");
      jwtAccessTokenConverter.afterPropertiesSet();
      jwtTokenStore = new JwtTokenStore(jwtAccessTokenConverter);
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
      return jwtTokenStore.readAuthentication(accessToken);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
      return jwtTokenStore.readAccessToken(accessToken);
    }
  }
}
