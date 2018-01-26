package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.config.OAuthProperties;
import org.cloudfoundry.credhub.util.RestTemplateFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;

@Component
@ConditionalOnProperty(value = "security.oauth2.enabled")
@Profile({"prod", "dev"})
public class OAuth2IssuerServiceImpl implements OAuth2IssuerService {

  private final URI authServerUri;
  private final RestTemplate restTemplate;

  private String issuer;

  @Autowired
  OAuth2IssuerServiceImpl(
      RestTemplateFactory restTemplateFactory,
      OAuthProperties oAuthProperties
  ) throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
    this.authServerUri = oAuthProperties.getIssuerPath();
    this.restTemplate = restTemplateFactory.createRestTemplate(oAuthProperties.getTrustStore(), oAuthProperties.getTrustStorePassword());
  }

  public void fetchIssuer() {
    ResponseEntity<HashMap> authResponse = restTemplate.getForEntity(authServerUri, HashMap.class);
    issuer = (String) authResponse.getBody().get("issuer");
  }

  @Override
  public String getIssuer() {
    return issuer;
  }


}
