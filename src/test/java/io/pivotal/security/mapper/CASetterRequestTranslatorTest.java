package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.view.CertificateAuthority;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.junit.Assert.assertThat;

import io.pivotal.security.view.ParameterizedValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class CASetterRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  private NamedCertificateAuthority entity;

  {
    wireAndUnwire(this);

    describe("populating entity from json", () -> {
      beforeEach(() -> {
        entity = new NamedCertificateAuthority(uniquify("foo"));
      });

      it("populates CA entity for valid scenarios", () -> {
        CertificateAuthority expected = new CertificateAuthority("root", "a", "b");
        String requestJson = "{\"type\":\"root\",\"value\":{\"certificate\":\"a\",\"private_key\":\"b\"}}";
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
        new CASetterRequestTranslator().populateEntityFromJson(entity, parsed);

        assertThat(CertificateAuthority.fromEntity(entity), BeanMatchers.theSameAs(expected));
      });

      itThrowsWithMessage("exception when certificate is missing", ParameterizedValidationException.class, "error.missing_ca_credentials", () -> {
        doTestInvalid("root", "", "a");
      });

      itThrowsWithMessage("exception when private key is missing", ParameterizedValidationException.class, "error.missing_ca_credentials", () -> {
        doTestInvalid("root", "b", "");
      });

      itThrowsWithMessage("exception when all credentials are missing", ParameterizedValidationException.class, "error.missing_ca_credentials", () -> {
        doTestInvalid("root", "", "");
      });

      itThrowsWithMessage("exception when type is invalid", ParameterizedValidationException.class, "error.type_invalid", () -> {
        doTestInvalid("invalid_ca_type", "b", "a");
      });
    });
  }

  private void doTestInvalid(String type, String certificate, String privateKey) throws ParameterizedValidationException {
    String requestJson = "{\"type\":" + type + ",\"value\":{\"certificate\":\"" + certificate + "\",\"private_key\":\"" + privateKey + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    new CASetterRequestTranslator().populateEntityFromJson(entity, parsed);
  }
}