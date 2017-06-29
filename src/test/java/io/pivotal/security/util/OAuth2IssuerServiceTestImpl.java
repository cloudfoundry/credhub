package io.pivotal.security.util;

import io.pivotal.security.auth.OAuth2IssuerService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Primary
@Component
public class OAuth2IssuerServiceTestImpl implements OAuth2IssuerService {
  @Override
  public String getIssuer() {
    return "https://example.com:8443/oauth/token";
  }
}
