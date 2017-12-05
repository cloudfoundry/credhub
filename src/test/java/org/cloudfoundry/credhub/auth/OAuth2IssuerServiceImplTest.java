package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.util.RestTemplateFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class OAuth2IssuerServiceImplTest {
  private static final String AUTH_SERVER = "https://example.com:1234/foo/bar";

  private OAuth2IssuerServiceImpl subject;

  private RestTemplate restTemplate;

  @Before
  public void setUp() throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
    String trustStore = "test-trust-store";
    String trustStorePassword = "test-trust-store-password";

    RestTemplateFactory restTemplateFactory = mock(RestTemplateFactory.class);
    restTemplate = mock(RestTemplate.class);

    when(restTemplateFactory.createRestTemplate(trustStore, trustStorePassword))
        .thenReturn(restTemplate);

    subject = new OAuth2IssuerServiceImpl(restTemplateFactory, AUTH_SERVER, trustStore, trustStorePassword);
  }

  @Test
  public void fetchIssuer_setsAndUpdatesTheIssuer() throws URISyntaxException {
    String issuer1 = "first-issuer";
    String issuer2 = "second-issuer";

    HashMap<String, String> uaaResponseBody = new HashMap<>();
    ResponseEntity<HashMap> uaaResponse = new ResponseEntity<>(uaaResponseBody, HttpStatus.OK);
    URI authServerUri = new URI(AUTH_SERVER.concat("/.well-known/openid-configuration"));

    uaaResponseBody.put("issuer", issuer1);

    when(restTemplate.getForEntity(authServerUri, HashMap.class)).thenReturn(uaaResponse);

    subject.fetchIssuer();

    assertThat(subject.getIssuer(), equalTo(issuer1));

    uaaResponseBody.clear();
    uaaResponseBody.put("issuer", issuer2);

    assertThat(subject.getIssuer(), equalTo(issuer1));

    subject.fetchIssuer();

    assertThat(subject.getIssuer(), equalTo(issuer2));
  }
}
