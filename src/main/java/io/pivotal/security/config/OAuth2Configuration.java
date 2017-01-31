package io.pivotal.security.config;

import io.pivotal.security.oauth.AuditOAuth2AccessDeniedHandler;
import io.pivotal.security.oauth.AuditOAuth2AuthenticationExceptionHandler;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.Assert;

import java.util.ArrayList;

import javax.annotation.PostConstruct;

@Configuration
@EnableResourceServer
@EnableWebSecurity
public class OAuth2Configuration extends ResourceServerConfigurerAdapter {

  @Autowired
  ResourceServerProperties resourceServerProperties;

  @Autowired
  AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler;

  @Autowired
  SecurityProperties securityProperties;

  @Autowired
  AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler;

  @PostConstruct
  public void init() {
    Assert.notNull(resourceServerProperties.getJwt().getKeyValue(), "Configuration property security.oauth2.resource.jwt.key-value must be set.");
    securityProperties.getUser().setName(RandomStringUtils.random(12));
    securityProperties.getUser().setRole(new ArrayList<>());
  }

  @Override
  public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    resources.resourceId(resourceServerProperties.getResourceId());
    resources.authenticationEntryPoint(auditOAuth2AuthenticationExceptionHandler);
    resources.accessDeniedHandler(auditOAuth2AccessDeniedHandler);
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/info").permitAll()
        .antMatchers("/poc").permitAll()
        .antMatchers("/health").permitAll()
        .antMatchers("/api/v1/**").access("#oauth2.hasScope('credhub.read') and #oauth2.hasScope('credhub.write')")
        .and()
        .httpBasic().disable();
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
    jwtAccessTokenConverter.setVerifierKey(resourceServerProperties.getJwt().getKeyValue());
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
}
