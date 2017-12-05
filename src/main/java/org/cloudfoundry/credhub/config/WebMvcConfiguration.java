package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.interceptor.AuditInterceptor;
import org.cloudfoundry.credhub.interceptor.UserContextInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {
  private final AuditInterceptor auditInterceptor;
  private final UserContextInterceptor userContextInterceptor;

  @Autowired
  public WebMvcConfiguration(
      AuditInterceptor auditInterceptor,
      UserContextInterceptor userContextInterceptor) {
    this.userContextInterceptor = userContextInterceptor;
    this.auditInterceptor = auditInterceptor;
  }

  @Override
  public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
    configurer.favorPathExtension(false);
  }

  @Override
  public void configurePathMatch(PathMatchConfigurer configurer) {
    configurer.setUseSuffixPatternMatch(false);
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    super.addInterceptors(registry);
    registry.addInterceptor(auditInterceptor).excludePathPatterns("/info", "/health", "/key-usage");
    registry.addInterceptor(userContextInterceptor).excludePathPatterns("/info", "/health", "/key-usage");
  }
}
