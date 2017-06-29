package io.pivotal.security.auth;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class OAuth2IssuerServiceImplTest {
  private static final String AUTH_SERVER = "https://example.com:1234/foo/bar";

  private RestTemplate restTemplate;

  private OAuth2IssuerServiceImpl subject;

  @Before
  public void setUp() throws URISyntaxException {
    restTemplate = mock(RestTemplate.class);
    subject = new OAuth2IssuerServiceImpl(AUTH_SERVER, restTemplate);
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
