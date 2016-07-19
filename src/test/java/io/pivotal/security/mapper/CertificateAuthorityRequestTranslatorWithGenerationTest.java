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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.refEq;
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

  {
    wireAndUnwire(this);

    it("creates view with specified parameters", () -> {
      CertificateSecretParameters expectedParams = new CertificateSecretParameters()
          .setCommonName("My Common Name")
          .setOrganization("Organization")
          .setOrganizationUnit("My Unit")
          .setLocality("My Locality")
          .setState("My State")
          .setCountry("My Country")
          .setKeyLength(512);
      String json = "{" +
          "\"type\":\"root\"," +
          "\"parameters\":{" +
          "\"common_name\":\"My Common Name\", " +
          "\"organization\": \"Organization\"," +
          "\"organization_unit\": \"My Unit\"," +
          "\"locality\": \"My Locality\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"key_length\": 512" +
          "}" +
          "}";
      when(certificateGenerator.generateCertificateAuthority(refEq(expectedParams)))
          .thenReturn(new CertificateAuthority("root", "theCert", "thePrivateKey"));
      DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(json);
      CertificateAuthority certificateAuthority = subject.createAuthorityFromJson(parsed);
      assertThat(certificateAuthority.getType(), equalTo("root"));
      assertThat(certificateAuthority.getCertificateAuthorityBody().getCertificate(), equalTo("theCert"));
      assertThat(certificateAuthority.getCertificateAuthorityBody().getPrivateKey(), equalTo("thePrivateKey"));
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
  }
}