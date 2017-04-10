package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class CertificateGenerationParametersTest {

  private CertificateGenerationParameters certificateGenerationParameters;

  {
    describe("#validate", () -> {

      it("validates extended key usages", () -> {
        try {
          certificateGenerationParameters = new CertificateGenerationParameters();
          certificateGenerationParameters.setCountry("My Country");
          certificateGenerationParameters.setIsCa(true);
          certificateGenerationParameters
              .setExtendedKeyUsage(new String[]{"client_auth", "server_off"});
          certificateGenerationParameters.validate();
        } catch (ParameterizedValidationException pve) {
          assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_extended_key_usage"));
          assertThat(pve.getParameter(), equalTo("server_off"));
        }
      });

      describe("with self_sign set to true and no ca name", () -> {
        itThrowsWithMessage("when is_ca is set to false", ParameterizedValidationException.class,
            "error.missing_signing_ca", () -> {
              certificateGenerationParameters = new CertificateGenerationParameters();
              certificateGenerationParameters.setCommonName("foo");
              certificateGenerationParameters.setIsCa(false);
              certificateGenerationParameters.validate();
            });
      });
      describe("when is_ca is set to true", () -> {
        it("should not throw an exception", () -> {
          certificateGenerationParameters = new CertificateGenerationParameters();
          certificateGenerationParameters.setCaName("test-ca");
          certificateGenerationParameters.setIsCa(true);
          certificateGenerationParameters.setCommonName("foo");
          certificateGenerationParameters.setDuration(10);
          certificateGenerationParameters.validate();
        });
      });
      itThrowsWithMessage("when duration is greater than 3650",
          ParameterizedValidationException.class, "error.invalid_duration", () -> {
            certificateGenerationParameters = new CertificateGenerationParameters();
            certificateGenerationParameters.setCaName("test-ca");
            certificateGenerationParameters.setCommonName("foo");
            certificateGenerationParameters.setDuration(3651);
            certificateGenerationParameters.validate();
          });

      itThrowsWithMessage("when all of DN parameters are empty",
          ParameterizedValidationException.class, "error.missing_certificate_parameters",
          () -> {
            certificateGenerationParameters = new CertificateGenerationParameters();
            certificateGenerationParameters.setCaName("test-ca");
            certificateGenerationParameters.setOrganization("");
            certificateGenerationParameters.setState("");
            certificateGenerationParameters.setCountry("");
            certificateGenerationParameters.setCommonName("");
            certificateGenerationParameters.setOrganizationUnit("");
            certificateGenerationParameters.setLocality("");
            certificateGenerationParameters.validate();
          });

      describe("when key lengths are invalid", () -> {
        itThrowsWithMessage("when key length is less than 2048",
            ParameterizedValidationException.class, "error.invalid_key_length", () -> {
              certificateGenerationParameters = new CertificateGenerationParameters();
              certificateGenerationParameters.setCaName("test-ca");
              certificateGenerationParameters.setCommonName("foo");
              certificateGenerationParameters.setKeyLength(1024);
              certificateGenerationParameters.validate();
            });

        itThrowsWithMessage("when key length is between 2048 and 3072",
            ParameterizedValidationException.class, "error.invalid_key_length", () -> {
              certificateGenerationParameters = new CertificateGenerationParameters();
              certificateGenerationParameters.setCaName("test-ca");
              certificateGenerationParameters.setCommonName("foo");
              certificateGenerationParameters.setKeyLength(2222);
              certificateGenerationParameters.validate();
            });

        itThrowsWithMessage("when key length is greater than 4096",
            ParameterizedValidationException.class, "error.invalid_key_length", () -> {
              certificateGenerationParameters = new CertificateGenerationParameters();
              certificateGenerationParameters.setCaName("test-ca");
              certificateGenerationParameters.setCommonName("foo");
              certificateGenerationParameters.setKeyLength(9192);
              certificateGenerationParameters.validate();
            });
      });

      describe("with alternate names", () -> {
        beforeEach(() -> {
          certificateGenerationParameters = new CertificateGenerationParameters();
          certificateGenerationParameters.setOrganization("my-org");
          certificateGenerationParameters.setState("NY");
          certificateGenerationParameters.setCountry("USA");
          certificateGenerationParameters.setSelfSigned(true);
        });

        it("are supported", () -> {
          certificateGenerationParameters
              .setAlternativeNames(
                  new String[]{"1.1.1.1", "example.com", "foo.pivotal.io", "*.pivotal.io"});

          certificateGenerationParameters.validate();
        });

        itThrows("with invalid special DNS characters throws a validation exception",
            ParameterizedValidationException.class, () -> {
              certificateGenerationParameters
                  .setAlternativeNames(new String[]{"foo!@#$%^&*()_-+=.com"});
              certificateGenerationParameters.validate();
            });

        itThrows("with space character throws a validation exception",
            ParameterizedValidationException.class, () -> {
              certificateGenerationParameters.setAlternativeNames(new String[]{"foo pivotal.io"});
              certificateGenerationParameters.validate();
            });

        itThrows("with invalid IP address throws a validation exception",
            ParameterizedValidationException.class, () -> {
              certificateGenerationParameters.setAlternativeNames(new String[]{"1.2.3.999"});
              certificateGenerationParameters.validate();
            });

        // email addresses are allowed in certificate spec,
        // but we do not allow them per PM requirements
        itThrows("with email address throws a validation exception",
            ParameterizedValidationException.class, () -> {
              certificateGenerationParameters.setAlternativeNames(new String[]{"x@y.com"});
              certificateGenerationParameters.validate();
            });

        itThrows("with URL throws a validation exception", ParameterizedValidationException.class,
            () -> {
              certificateGenerationParameters.setAlternativeNames(new String[]{"https://foo.com"});
              certificateGenerationParameters.validate();
            });
      });

      describe("with extended key usages", () -> {
        itThrows("with space character throws a validation exception",
            ParameterizedValidationException.class, () -> {
              certificateGenerationParameters = new CertificateGenerationParameters();
              certificateGenerationParameters.setOrganization("my-org");
              certificateGenerationParameters.setState("NY");
              certificateGenerationParameters.setCountry("USA");
              certificateGenerationParameters
                  .setExtendedKeyUsage(new String[]{"not an extended key"});
              certificateGenerationParameters.validate();
            });
      });
    });

  }
}