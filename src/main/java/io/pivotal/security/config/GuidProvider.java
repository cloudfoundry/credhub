package io.pivotal.security.config;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class GuidProvider {
  public String getUUID() {
    return UUID.randomUUID().toString();
  }
}