package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import io.pivotal.security.secret.Certificate;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import org.junit.runner.RunWith;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Security;

@RunWith(Spectrum.class)
public class CertificateAuthorityServiceTest {
  CertificateAuthorityService certificateAuthorityService;
  SecretDataService secretDataService;
  Certificate certificate;
  NamedCertificateSecret namedCertificateSecret;

  {
    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());

      certificate = new Certificate(null, SELF_SIGNED_CA_CERT, "my-key");
      namedCertificateSecret = mock(NamedCertificateSecret.class);

      secretDataService = mock(SecretDataService.class);
      certificateAuthorityService = new CertificateAuthorityService(secretDataService);
    });

    afterEach(() -> {
      Security.removeProvider("BC");
    });

    describe("when a CA does not exist", () -> {
      beforeEach(() -> {
        when(secretDataService.findMostRecent(any(String.class))).thenReturn(null);
      });

      itThrowsWithMessage("error.ca_not_found", ParameterizedValidationException.class, "error.ca_not_found", () -> {
        certificateAuthorityService.findMostRecent("any ca name");
      });
    });

    describe("when a CA does exist", () -> {
      beforeEach(() -> {
        when(secretDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateSecret);
        when(namedCertificateSecret.getPrivateKey()).thenReturn("my-key");
        when(namedCertificateSecret.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);
      });

      it("returns it", () -> {
        assertThat(certificateAuthorityService.findMostRecent("my-ca-name"), samePropertyValuesAs(certificate));
      });
    });

    describe("when the secret found isn't a certificate", () -> {
      beforeEach(() -> {
        when(secretDataService.findMostRecent("actually-a-password")).thenReturn(new NamedPasswordSecret());
      });

      itThrowsWithMessage("error.ca_not_found", ParameterizedValidationException.class, "error.ca_not_found", () -> {
        certificateAuthorityService.findMostRecent("actually-a-password");
      });
    });

    describe("when the certificate found isn't a ca", () -> {
      beforeEach(() -> {
        NamedCertificateSecret notACertificateAuthority = mock(NamedCertificateSecret.class);
        when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
        when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
        when(secretDataService.findMostRecent("just-a-certificate")).thenReturn(notACertificateAuthority);
      });

      itThrowsWithMessage("error.cert_not_ca", ParameterizedValidationException.class, "error.cert_not_ca", () -> {
        certificateAuthorityService.findMostRecent("just-a-certificate");
      });
    });
  }
}
