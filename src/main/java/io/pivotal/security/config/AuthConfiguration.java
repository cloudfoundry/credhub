package io.pivotal.security.config;

import io.pivotal.security.oauth.AuditOAuth2AccessDeniedHandler;
import io.pivotal.security.oauth.AuditOAuth2AuthenticationExceptionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Configuration
@EnableResourceServer
@EnableWebSecurity
public class AuthConfiguration extends ResourceServerConfigurerAdapter {
  private final ResourceServerProperties resourceServerProperties;
  private final AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler;
  private final AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler;

  @Autowired
  AuthConfiguration(
      ResourceServerProperties resourceServerProperties,
      AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler,
      AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler
  ) {
    this.resourceServerProperties = resourceServerProperties;
    this.auditOAuth2AuthenticationExceptionHandler = auditOAuth2AuthenticationExceptionHandler;
    this.auditOAuth2AccessDeniedHandler = auditOAuth2AccessDeniedHandler;
  }

  @Override
  public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    resources.resourceId(resourceServerProperties.getResourceId());
    resources.authenticationEntryPoint(auditOAuth2AuthenticationExceptionHandler);
    resources.accessDeniedHandler(auditOAuth2AccessDeniedHandler);
    resources.stateless(false);
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/info").permitAll()
        .antMatchers("/health").permitAll()
        .antMatchers("/api/v1/**").access("hasRole('MTLS_USER') or (#oauth2.hasScope('credhub.read') and #oauth2.hasScope('credhub.write'))");

    http.x509().userDetailsService(mTLSUserDetailsService());

    http.httpBasic().disable();
  }

  private UserDetailsService mTLSUserDetailsService() {
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User(username, "", AuthorityUtils.createAuthorityList("ROLE_MTLS_USER"));
      }
    };
  }
}
