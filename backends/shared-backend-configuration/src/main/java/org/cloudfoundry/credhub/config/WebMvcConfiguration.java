package org.cloudfoundry.credhub.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import org.cloudfoundry.credhub.ManagementInterceptor;
import org.cloudfoundry.credhub.interceptors.AuditInterceptor;
import org.cloudfoundry.credhub.interceptors.UserContextInterceptor;

@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {
  private final AuditInterceptor auditInterceptor;
  private final UserContextInterceptor userContextInterceptor;
  private final ManagementInterceptor managementInterceptor;

  @Autowired
  public WebMvcConfiguration(
    final AuditInterceptor auditInterceptor,
    final UserContextInterceptor userContextInterceptor,
    final ManagementInterceptor managementInterceptor
  ) {
    super();
    this.userContextInterceptor = userContextInterceptor;
    this.auditInterceptor = auditInterceptor;
    this.managementInterceptor = managementInterceptor;
  }

  @Override
  public void configureContentNegotiation(final ContentNegotiationConfigurer configurer) {
    configurer.favorPathExtension(false);
  }

  @Override
  public void configurePathMatch(final PathMatchConfigurer configurer) {
    configurer.setUseSuffixPatternMatch(false);
  }

  @Override
  public void addInterceptors(final InterceptorRegistry registry) {
    registry.addInterceptor(auditInterceptor).excludePathPatterns(
      "/info",
      "/health",
      "/**/key-usage",
      "/version",
      "/docs/index.html"
    );
    registry.addInterceptor(managementInterceptor);
    registry.addInterceptor(userContextInterceptor).excludePathPatterns(
      "/info",
      "/health",
      "/**/key-usage",
      "/management",
      "/docs/index.html"
    );
  }
}
