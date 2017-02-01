package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateAuthorityServiceTest {
  CertificateAuthorityService certificateAuthorityService;

  CertificateAuthorityDataService certificateAuthorityDataService;
  SecretDataService secretDataService;

  Certificate certificate;
  NamedCertificateAuthority namedCertificateAuthority;
  NamedCertificateSecret namedCertificateSecret;

  {
    beforeEach(() -> {
      certificate = new Certificate(null, "my-cert", "my-key");
      namedCertificateAuthority = mock(NamedCertificateAuthority.class);
      namedCertificateSecret = mock(NamedCertificateSecret.class);

      certificateAuthorityDataService = mock(CertificateAuthorityDataService.class);
      secretDataService = mock(SecretDataService.class);
      certificateAuthorityService = new CertificateAuthorityService(certificateAuthorityDataService, secretDataService);
    });

    describe("when the user is asking for the default CA", () -> {
      describe("when it doesn't exist in the certificateAuthorityDataService", () -> {
        beforeEach(() -> {
          when(certificateAuthorityDataService.findMostRecent("default")).thenReturn(null);
        });

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
    });

    describe("when a CA does not exist", () -> {
      beforeEach(() -> {
        when(certificateAuthorityDataService.findMostRecent(any(String.class))).thenReturn(null);
        when(secretDataService.findMostRecent(any(String.class))).thenReturn(null);
      });

      itThrowsWithMessage("error.ca_not_found", ParameterizedValidationException.class, "error.ca_not_found", () -> {
        certificateAuthorityService.findMostRecent("any ca name");
      });
    });

    describe("when a CA does exist", () -> {
      describe("in the secretDataService but not in the namedCertificateAuthorityDataService", () -> {
        beforeEach(() -> {
          when(certificateAuthorityDataService.findMostRecent("my-ca-name")).thenReturn(null);
          when(secretDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateSecret);
          when(namedCertificateSecret.getPrivateKey()).thenReturn("my-key");
          when(namedCertificateSecret.getCertificate()).thenReturn("my-cert");
        });

        it("returns it", () -> {
          assertThat(certificateAuthorityService.findMostRecent("my-ca-name"), samePropertyValuesAs(certificate));
        });
      });

      describe("in the namedCertificateAuthorityDataService but not in the secretDataService", () -> {
        beforeEach(() -> {
          when(certificateAuthorityDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateAuthority);
          when(secretDataService.findMostRecent("my-ca-name")).thenReturn(null);
          when(namedCertificateAuthority.getPrivateKey()).thenReturn("my-key");
          when(namedCertificateAuthority.getCertificate()).thenReturn("my-cert");
        });

        it("returns it", () -> {
          assertThat(certificateAuthorityService.findMostRecent("my-ca-name"), samePropertyValuesAs(certificate));
        });
      });

      describe("in both namedCertificateAuthorityDataService and secretDataService", () -> {
        beforeEach(() -> {
          when(certificateAuthorityDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateAuthority);
          when(secretDataService.findMostRecent("my-ca-name")).thenReturn(namedCertificateSecret);
          when(namedCertificateSecret.getPrivateKey()).thenReturn("my-key");
          when(namedCertificateSecret.getCertificate()).thenReturn("my-cert");
        });

        it("prefers the certificate authority found in secretDataService", () -> {
          assertThat(certificateAuthorityService.findMostRecent("my-ca-name"), samePropertyValuesAs(certificate));
        });
      });
    });
  }
}
