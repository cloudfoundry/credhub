package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CASetterRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  private NamedCertificateAuthority entity;

  private CASetterRequestTranslator subject;

  {
    wireAndUnwire(this, false);

    describe("populating entity from json", () -> {
      beforeEach(() -> {
        entity = new NamedCertificateAuthority("foo");
        subject = new CASetterRequestTranslator();
      });

      it("validates the json keys", () -> {
        String requestJson =
            "{" +
                "\"type\":\"root\"," +
                "\"name\":\"foo\"," +
                "\"value\":{" +
                "\"certificate\":\"a\"," +
                "\"private_key\":\"b\"}}";
        DocumentContext parsed = jsonPath.parse(requestJson);
        subject.validateJsonKeys(parsed);
        // no exception
      });

      it("populates CA entity for valid scenarios", () -> {
        String requestJson = "{\"type\":\"root\",\"value\":{\"certificate\":\"a\",\"private_key\":\"b\"}}";
        DocumentContext parsed = jsonPath.parse(requestJson);

        subject.populateEntityFromJson(entity, parsed);

        assertThat(entity.getType(), equalTo("root"));
        assertThat(entity.getCertificate(), equalTo("a"));
        assertThat(entity.getPrivateKey(), equalTo("b"));
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

    describe("when random parameters are provided", () -> {
      itThrows("it rejects request", ParameterizedValidationException.class, () -> {
        String requestJson = "{\"type\":\"root\",\"foo\":\"bar\",\"value\":{\"certificate\":\"a\",\"private_key\":\"b\"}}";
        DocumentContext parsed = jsonPath.parse(requestJson);

        subject.validateJsonKeys(parsed);
      });
    });
  }

  private void doTestInvalid(String type, String certificate, String privateKey) throws ParameterizedValidationException {
    String requestJson = "{\"type\":" + type + ",\"value\":{\"certificate\":\"" + certificate + "\",\"private_key\":\"" + privateKey + "\"}}";

    DocumentContext parsed = jsonPath.parse(requestJson);
    subject.populateEntityFromJson(entity, parsed);
  }
}
