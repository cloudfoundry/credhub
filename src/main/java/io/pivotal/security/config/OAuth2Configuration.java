package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.util.Assert;

import javax.annotation.PostConstruct;

@Configuration
@EnableResourceServer
@EnableWebSecurity
public class OAuth2Configuration extends ResourceServerConfigurerAdapter {

  @Autowired
  ResourceServerProperties resourceServerProperties;

  @PostConstruct
  public void init() {
    Assert.notNull(resourceServerProperties.getJwt().getKeyValue(), "Configuration property security.oauth2.resource.jwt.key-value must be set.");
  }

  @Override
  public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    resources.resourceId(resourceServerProperties.getResourceId());
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/info").permitAll()
        .antMatchers("/health").permitAll()
        .antMatchers("/api/v1/data/**").access("#oauth2.hasScope('credhub.read') and #oauth2.hasScope('credhub.write')");
  }
}
