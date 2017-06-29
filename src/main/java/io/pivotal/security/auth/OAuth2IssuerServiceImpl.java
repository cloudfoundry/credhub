package io.pivotal.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.HashMap;

@Component
public class OAuth2IssuerServiceImpl implements OAuth2IssuerService {
  private final static String ISSUER_PATH = "/.well-known/openid-configuration";

  private final URI authServerUri;
  private final RestTemplate restTemplate;

  private String issuer;

  @Autowired
  OAuth2IssuerServiceImpl(
      @Value("${auth_server.url}") String authServer,
      RestTemplate restTemplate
  ) throws URISyntaxException {
    this.authServerUri = getResolvedAuthServerUri(authServer);
    this.restTemplate = restTemplate;
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
