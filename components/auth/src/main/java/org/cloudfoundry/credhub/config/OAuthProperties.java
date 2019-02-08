package org.cloudfoundry.credhub.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("auth-server")
@ConditionalOnProperty("security.oauth2.enabled")
public class OAuthProperties {
  private final static String ISSUER_PATH = "/.well-known/openid-configuration";
  private final static String JWK_KEYS_PATH = "/token_keys";

  @Value("${internal_url:#{null}}")
  private String internalUrl;
  private String url;
  private String trustStore;
  private String trustStorePassword;

  public URI getIssuerPath() throws URISyntaxException {
    return getResolvedUri(ISSUER_PATH);
  }

  public String getJwkKeysPath() throws URISyntaxException {
    return getResolvedUri(JWK_KEYS_PATH).toString();
  }

  public void setInternalUrl(final String internalUrl) {
    this.internalUrl = internalUrl;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(final String url) {
    this.url = url;
  }

  public String getTrustStore() {
    return trustStore;
  }

  public void setTrustStore(final String trustStore) {
    this.trustStore = trustStore;
  }

  public String getTrustStorePassword() {
    return trustStorePassword;
  }

  public void setTrustStorePassword(final String trustStorePassword) {
    this.trustStorePassword = trustStorePassword;
  }


  private URI getResolvedUri(final String extension) throws URISyntaxException {
    final String authServer = internalUrl != null ? internalUrl : url;
    final URI base = new URI(authServer);
    final String path = Paths.get(base.getPath(), extension).toString();
    return base.resolve(path);
  }
}
