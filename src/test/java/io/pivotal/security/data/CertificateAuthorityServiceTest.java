package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateAuthorityServiceTest {
  CertificateAuthorityService certificateAuthorityService;

  CertificateAuthorityDataService certificateAuthorityDataService;

  NamedCertificateAuthority someCA;

  {
    beforeEach(() -> {
      certificateAuthorityDataService = mock(CertificateAuthorityDataService.class); // Why?
      certificateAuthorityService = new CertificateAuthorityService(certificateAuthorityDataService);
    });

    describe("when the user is asking for the default CA", () -> {
      describe("when it doesn't exist", () -> {
        beforeEach( () -> {
          when(certificateAuthorityDataService.findMostRecent(any(String.class))).thenReturn(null);
        });

        it("throws a validation exception", () -> {
          try {
            certificateAuthorityService.findMostRecent("default");
            fail();
          } catch (ParameterizedValidationException ve) {
            assertThat(ve.getMessage(), equalTo("error.default_ca_required"));
          }
        });
      });
    });

    describe("when a CA does not exist", () -> {
      beforeEach( () -> {
        when(certificateAuthorityDataService.findMostRecent(any(String.class))).thenReturn(null);
      });

      it("throws a validation exception", () -> {
        try {
          certificateAuthorityService.findMostRecent("any ca name");
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.ca_not_found"));
        }
      });
    });

    describe("when a CA does exist", () -> {
      beforeEach( () -> {
        someCA = mock(NamedCertificateAuthority.class);
        when(certificateAuthorityDataService.findMostRecent("my ca name")).thenReturn(someCA);
      });

      it("returns it", () -> {
        assertThat(certificateAuthorityService.findMostRecent("my ca name"), equalTo(someCA));
      });
    });
  }
}