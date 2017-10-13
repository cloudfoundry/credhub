package io.pivotal.security.config;

import io.pivotal.security.interceptor.AuditInterceptor;
import io.pivotal.security.controller.v1.RequestUuidArgumentResolver;
import io.pivotal.security.interceptor.UserContextInterceptor;
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
  private final RequestUuidArgumentResolver requestUuidArgumentResolver;
  private final AuditInterceptor auditInterceptor;
  private final UserContextInterceptor userContextInterceptor;

  @Autowired
  public WebMvcConfiguration(
      RequestUuidArgumentResolver requestUuidArgumentResolver,
      AuditInterceptor auditInterceptor,
      UserContextInterceptor userContextInterceptor) {
    this.userContextInterceptor = userContextInterceptor;
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
    argumentResolvers.add(requestUuidArgumentResolver);
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    super.addInterceptors(registry);
    registry.addInterceptor(auditInterceptor).excludePathPatterns("/info", "/health", "/key-usage");
    registry.addInterceptor(userContextInterceptor).excludePathPatterns("/info", "/health", "/key-usage");
  }
}
