package io.pivotal.security.config;

import io.pivotal.security.auth.AuditOAuth2AccessDeniedHandler;
import io.pivotal.security.auth.AuditOAuth2AuthenticationExceptionHandler;
import io.pivotal.security.auth.PreAuthenticationFailureFilter;
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
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

@Configuration
@EnableResourceServer
@EnableWebSecurity
public class AuthConfiguration extends ResourceServerConfigurerAdapter {
  // Only valid for v4 UUID by design.
  private static final String VALID_MTLS_ID = "CN=.+,OU=(app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-"
      + "[a-f0-9]{4}-[a-f0-9]{12})(?:,|$)";

  private final ResourceServerProperties resourceServerProperties;
  private final AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler;
  private final AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler;
  private final PreAuthenticationFailureFilter preAuthenticationFailureFilter;

  @Autowired
  AuthConfiguration(
      ResourceServerProperties resourceServerProperties,
      AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler,
      AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler,
      PreAuthenticationFailureFilter preAuthenticationFailureFilter
  ) {
    this.resourceServerProperties = resourceServerProperties;
    this.auditOAuth2AuthenticationExceptionHandler = auditOAuth2AuthenticationExceptionHandler;
    this.auditOAuth2AccessDeniedHandler = auditOAuth2AccessDeniedHandler;
    this.preAuthenticationFailureFilter = preAuthenticationFailureFilter;
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
    http.addFilterBefore(preAuthenticationFailureFilter, X509AuthenticationFilter.class);

    http
        .authorizeRequests()
        .antMatchers("/info").permitAll()
        .antMatchers("/health").permitAll()
        .antMatchers("/api/v1/**").access("hasRole('MTLS_USER') or "
        + "(#oauth2.hasScope('credhub.read') and #oauth2.hasScope('credhub.write'))");

    http.x509()
        .subjectPrincipalRegex(VALID_MTLS_ID)
        .userDetailsService(mtlsSUserDetailsService());

    http.httpBasic().disable();
  }

  private UserDetailsService mtlsSUserDetailsService() {
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User(username, "", AuthorityUtils.createAuthorityList("ROLE_MTLS_USER"));
      }
    };
  }
}
