//package io.pivotal.security.audit;
//
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class RequestUuidFilterRegistration {
//  @Bean
//  FilterRegistrationBean requestUuidFilterRegistrationBean() {
//    FilterRegistrationBean registration = new FilterRegistrationBean();
//    registration.setFilter(requestUuidFilter());
//    registration.setOrder(1);
//    return registration;
//  }
//
//  @Bean
//  RequestUuidFilter requestUuidFilter() {
//    return new RequestUuidFilter();
//  }
//}
