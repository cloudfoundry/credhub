package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class CertificateSetRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  private CertificateSetRequestTranslator subject;

  private NamedCertificateSecret entity;

  {
    wireAndUnwire(this);

    describe("populating entity from json", () -> {

      beforeEach(() -> {
        subject = new CertificateSetRequestTranslator();
        entity = subject.makeEntity("Foo");
      });

      it("creates an entity when all fields are present", () -> {
        checkEntity("my-root", "my-cert", "my-priv", "my-root", "my-cert", "my-priv");
        checkEntity("my-root", "my-cert", null, "my-root", "my-cert", "");
        checkEntity("my-root", null, "my-priv", "my-root", "", "my-priv");
        checkEntity("my-root", null, null, "my-root", "", "");
        checkEntity(null, "my-cert", "my-priv", "", "my-cert", "my-priv");
        checkEntity(null, "my-cert", null, "", "my-cert", "");
        checkEntity(null, null, "my-priv", "", "", "my-priv");
      });

      itThrowsWithMessage("exception when all values are absent", ValidationException.class, "error.missing_certificate_credentials", () -> {
        checkEntity(null, null, null, "", "", "");
      });
    });
  }

  private void checkEntity(String expectedRoot, String expectedCertificate, String expectedPrivateKey, String root, String certificate, String privateKey) {
    String requestJson = createJson(root, certificate, privateKey);
    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    subject.populateEntityFromJson(entity, parsed);
    assertThat(entity.getCa(), equalTo(expectedRoot));
    assertThat(entity.getCertificate(), equalTo(expectedCertificate));
    assertThat(entity.getPrivateKey(), equalTo(expectedPrivateKey));
  }

  private String createJson(String root, String certificate, String privateKey) {
    return "{\"type\":\"certificate\",\"value\":{\"ca\":\"" + root + "\",\"certificate\":\"" + certificate + "\",\"private_key\":\"" + privateKey + "\"}}";
  }
}