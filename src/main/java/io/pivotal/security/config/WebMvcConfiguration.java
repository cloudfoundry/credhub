package io.pivotal.security.config;

import io.pivotal.security.audit.AuditInterceptor;
import io.pivotal.security.controller.v1.RequestUuidArgumentResolver;
import io.pivotal.security.controller.v1.UserContextArgumentResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.List;

@Configuration
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {
  private final UserContextArgumentResolver userContextArgumentResolver;
  private final RequestUuidArgumentResolver requestUuidArgumentResolver;
  private final AuditInterceptor auditInterceptor;

  @Autowired
  public WebMvcConfiguration(
      UserContextArgumentResolver userContextArgumentResolver,
      RequestUuidArgumentResolver requestUuidArgumentResolver,
      AuditInterceptor auditInterceptor
  ) {
    this.userContextArgumentResolver = userContextArgumentResolver;
    this.requestUuidArgumentResolver = requestUuidArgumentResolver;
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
  public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
    argumentResolvers.add(userContextArgumentResolver);
    argumentResolvers.add(requestUuidArgumentResolver);
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    super.addInterceptors(registry);
    registry.addInterceptor(auditInterceptor).excludePathPatterns("/info", "/health");
  }
}
