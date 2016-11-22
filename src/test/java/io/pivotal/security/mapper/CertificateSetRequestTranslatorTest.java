package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CertificateSetRequestTranslatorTest {

  @Autowired
  private ParseContext jsonPath;

  private CertificateSetRequestTranslator subject;

  private NamedCertificateSecret entity;

  {
    wireAndUnwire(this, false);

    describe("populating entity from json", () -> {

      beforeEach(() -> {
        subject = new CertificateSetRequestTranslator();
        entity = new NamedCertificateSecret("Foo");
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

      itThrowsWithMessage("exception when all values are absent", ParameterizedValidationException.class, "error.missing_certificate_credentials", () -> {
        checkEntity(null, null, null, "", "", "");
      });
    });

    describe("#validateJsonKeys", () -> {
      it("should pass if given correct parameters", () -> {
        String requestBody = "{" +
            "\"type\":\"certificate\"," +
            "\"name\":\"someName\"," +
            "\"overwrite\":false," +
            "\"value\":{" +
            "\"ca\":\"my-ca-so-awesome\"," +
            "\"certificate\":\"certstuffs\"," +
            "\"private_key\":\"someprivatekey\"" +
            "}" +
        "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        // pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"certificate\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });
  }

  private void checkEntity(String expectedRoot, String expectedCertificate, String expectedPrivateKey, String root, String certificate, String privateKey) {
    String requestJson = createJson(root, certificate, privateKey);
    DocumentContext parsed = jsonPath.parse(requestJson);
    subject.populateEntityFromJson(entity, parsed);
    assertThat(entity.getCa(), equalTo(expectedRoot));
    assertThat(entity.getCertificate(), equalTo(expectedCertificate));
    assertThat(entity.getPrivateKey(), equalTo(expectedPrivateKey));
  }

  private String createJson(String root, String certificate, String privateKey) {
    return "{\"type\":\"certificate\",\"value\":{\"ca\":\"" + root + "\",\"certificate\":\"" + certificate + "\",\"private_key\":\"" + privateKey + "\"}}";
  }
}
