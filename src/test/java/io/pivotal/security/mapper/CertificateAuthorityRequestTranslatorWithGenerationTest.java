package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.refEq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CertificateAuthorityRequestTranslatorWithGenerationTest {
  @Autowired
  private Configuration jsonConfiguration;

  @InjectMocks
  @Autowired
  CertificateAuthorityRequestTranslatorWithGeneration subject;

  @Mock
  BCCertificateGenerator certificateGenerator;

  @Spy
  CertificateSecretParameters certificateSecretParameters;

  private DocumentContext parsed;

  {
    wireAndUnwire(this);

    describe("when all parameters are provided", () -> {
      beforeEach(() -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"Organization\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"key_length\": 2048," +
            "\"duration\": 364" +
            "}" +
            "}";
        parsed = JsonPath.using(jsonConfiguration).parse(json);
      });

      it("creates view with specified parameters", () -> {
        CertificateSecretParameters expectedParams = new CertificateSecretParameters()
            .setCommonName("My Common Name")
            .setOrganization("Organization")
            .setOrganizationUnit("My Unit")
            .setLocality("My Locality")
            .setState("My State")
            .setCountry("My Country")
            .setKeyLength(2048)
            .setDurationDays(364);

        when(certificateGenerator.generateCertificateAuthority(refEq(expectedParams)))
            .thenReturn(new CertificateAuthority("root", "theCert", "thePrivateKey"));
        CertificateAuthority certificateAuthority = subject.createAuthorityFromJson(parsed);
        assertThat(certificateAuthority.getType(), equalTo("root"));
        assertThat(certificateAuthority.getCertificateAuthorityBody().getCertificate(), equalTo("theCert"));
        assertThat(certificateAuthority.getCertificateAuthorityBody().getPrivateKey(), equalTo("thePrivateKey"));
      });

      it("validates parameters", () -> {
        when(certificateGenerator.generateCertificateAuthority(refEq(certificateSecretParameters)))
            .thenReturn(new CertificateAuthority("root", "theCert", "thePrivateKey"));
        subject.createAuthorityFromJson(parsed);
        Mockito.verify(certificateSecretParameters, times(1)).validate();
      });

      it("returns error when type is not 'root'", () -> {
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse("{\"type\":\"notRoot\"}");
        try {
          subject.createAuthorityFromJson(parsed);
          fail();
        } catch (ValidationException e) {
          assertThat(e.getMessage(), equalTo("error.bad_authority_type"));
        }
      });
    });
  }
}