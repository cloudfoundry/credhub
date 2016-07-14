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

    it("creates view class with hardwired parameters", () -> {
      CertificateSecretParameters hardwiredParams = new CertificateSecretParameters()
          .setOrganization("Organization")
          .setState("CA")
          .setCountry("US")
          .setKeyLength(2048)
          .setDurationDays(365);

      when(certificateGenerator.generateCertificateAuthority(refEq(hardwiredParams))).thenReturn(new CertificateAuthority("root", "theCert", "thePrivateKey"));
      DocumentContext parsed = JsonPath.using(jsonConfiguration).parse("{\"type\":\"root\"}");
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