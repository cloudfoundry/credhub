package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class DevKeyProvider {
  @Value("${encryption.dev-key:D673ACD01DA091B08144FBC8C0B5F524}")
  private String devKey;

  public String getDevKey() {
    return devKey;
  }
}