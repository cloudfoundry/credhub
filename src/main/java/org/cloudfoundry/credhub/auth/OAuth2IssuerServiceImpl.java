package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.util.RestTemplateFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;

@Component
@ConditionalOnProperty(value = "security.oauth2.enabled")
@Profile({"prod", "dev"})
public class OAuth2IssuerServiceImpl implements OAuth2IssuerService {
  private final static String ISSUER_PATH = "/.well-known/openid-configuration";

  private final URI authServerUri;
  private final RestTemplate restTemplate;

  private String issuer;

  @Autowired
  OAuth2IssuerServiceImpl(
      RestTemplateFactory restTemplateFactory,
      @Value("#{@environment.getProperty('auth_server.internal_url') ?: @environment.getProperty('auth_server.url')}") String authServer,
      @Value("${auth_server.trust_store:}") String trustStore,
      @Value("${auth_server.trust_store_password:}") String trustStorePassword
  ) throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
    this.authServerUri = getResolvedAuthServerUri(authServer);
    this.restTemplate = restTemplateFactory.createRestTemplate(trustStore, trustStorePassword);
  }

  public void fetchIssuer() {
    ResponseEntity<HashMap> authResponse = restTemplate.getForEntity(authServerUri, HashMap.class);
    issuer = (String) authResponse.getBody().get("issuer");
  }

  @Override
  public String getIssuer() {
    return issuer;
  }

  private static URI getResolvedAuthServerUri(String authServer) throws URISyntaxException {
    URI base = new URI(authServer);
    String path = Paths.get(base.getPath(), ISSUER_PATH).toString();
    return base.resolve(path);
  }
}
