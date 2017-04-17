package io.pivotal.security.data;

import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.pivotal.security.config.BouncyCastleProviderConfiguration;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.secret.Certificate;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class CertificateAuthorityServiceTest {

  CertificateAuthorityService certificateAuthorityService;
  SecretDataService secretDataService;
  Certificate certificate;
  NamedCertificateSecret namedCertificateSecret;

  @Before
  public void beforeEach() {
    certificate = new Certificate(null, SELF_SIGNED_CA_CERT, "my-key");
    namedCertificateSecret = mock(NamedCertificateSecret.class);

    secretDataService = mock(SecretDataService.class);
    certificateAuthorityService = new CertificateAuthorityService(secretDataService);

    new BouncyCastleProviderConfiguration().bouncyCastleProvider();
  }

  @Test
  public void findMostRecent_whenACaDoesNotExist_throwsException() {
    when(secretDataService.findMostRecent(any(String.class))).thenReturn(null);

    try {
      certificateAuthorityService.findMostRecent("any ca name");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.ca_not_found"));
    }
  }

  @Test
  public void findMostRecent_givenExistingCa_returnsTheCa() {
    when(secretDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateSecret);
    when(namedCertificateSecret.getPrivateKey()).thenReturn("my-key");
    when(namedCertificateSecret.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);

    assertThat(certificateAuthorityService.findMostRecent("my-ca-name"),
        samePropertyValuesAs(certificate));
  }

  @Test
  public void findMostRecent_whenSecretIsNotACa_throwsException() {
    when(secretDataService.findMostRecent("actually-a-password"))
        .thenReturn(new NamedPasswordSecret());

    try {
      certificateAuthorityService.findMostRecent("actually-a-password");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.ca_not_found"));
    }
  }

  @Test
  public void findMostRecent_whenCertificateIsNotACa_throwsException() {
    NamedCertificateSecret notACertificateAuthority = mock(NamedCertificateSecret.class);
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(secretDataService.findMostRecent("just-a-certificate"))
        .thenReturn(notACertificateAuthority);



    try {
      certificateAuthorityService.findMostRecent("just-a-certificate");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.cert_not_ca"));
    }
  }
}
