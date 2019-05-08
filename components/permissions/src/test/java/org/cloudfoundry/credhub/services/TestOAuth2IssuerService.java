package org.cloudfoundry.credhub.services;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.auth.OAuth2IssuerService;

@Service
@Profile("unit-test")
public class TestOAuth2IssuerService implements OAuth2IssuerService {
  @Override
  public String getIssuer() {
    return "https://example.com:8443/oauth/token";
  }
}
