package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateAuthorityServiceTest {
  CertificateAuthorityService certificateAuthorityService;
  SecretDataService secretDataService;
  Certificate certificate;
  NamedCertificateSecret namedCertificateSecret;

  {
    beforeEach(() -> {
      certificate = new Certificate(null, "my-cert", "my-key");
      namedCertificateSecret = mock(NamedCertificateSecret.class);

      secretDataService = mock(SecretDataService.class);
      certificateAuthorityService = new CertificateAuthorityService(secretDataService);
    });

    describe("when the user is asking for the default CA", () -> {
      describe("and the default exists in the namedSecretRepository", () -> {
        beforeEach(() -> {
          when(secretDataService.findMostRecent("default")).thenReturn(namedCertificateSecret);
          when(namedCertificateSecret.getPrivateKey()).thenReturn("my-key");
          when(namedCertificateSecret.getCertificate()).thenReturn("my-cert");
        });

        it("returns it", () -> {
          assertThat(certificateAuthorityService.findMostRecent("default"), samePropertyValuesAs(certificate));
        });
      });

      describe("when both data services cannot find the default CA", () -> {
        itThrowsWithMessage("error.default_ca_required", ParameterizedValidationException.class, "error.default_ca_required", () -> {
          certificateAuthorityService.findMostRecent("default");
        });
      });
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
        when(namedCertificateSecret.getCertificate()).thenReturn("my-cert");
      });

      it("returns it", () -> {
        assertThat(certificateAuthorityService.findMostRecent("my-ca-name"), samePropertyValuesAs(certificate));
      });
    });
  }
}
