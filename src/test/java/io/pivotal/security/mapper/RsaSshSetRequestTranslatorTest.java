package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.exceptions.ParameterizedValidationException;
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
public class RsaSshSetRequestTranslatorTest {
  @Autowired
  private ParseContext jsonPath;

  private RsaSshSetRequestTranslator subject;

  private NamedRsaSecret entity;

  @Autowired
  private Encryptor encryptor;

  {
    wireAndUnwire(this, false);

    describe("populating entity from json", () -> {

      beforeEach(() -> {
        subject = new RsaSshSetRequestTranslator();
        entity = new NamedRsaSecret("Foo");
        entity.setEncryptor(encryptor);
      });

      it("creates an entity when all fields are present", () -> {
        checkEntity("my-public-key", "my-private-key", "my-public-key", "my-private-key");
        checkEntity("my-public-key", null, "my-public-key", "");
        checkEntity(null, "my-private-key", "", "my-private-key");
      });

      itThrowsWithMessage("exception when both values are absent", ParameterizedValidationException.class, "error.missing_rsa_ssh_parameters", () -> {
        checkEntity(null, null, "", "");
      });
    });

    describe("#validateJsonKeys", () -> {
      it("should pass if given correct parameters", () -> {
        String requestBody = "{" +
            "\"type\":\"rsa\"," +
            "\"name\":\"someName\"," +
            "\"overwrite\":false," +
            "\"value\":{" +
            "\"public_key\":\"somepublickey\"," +
            "\"private_key\":\"someprivatekey\"" +
            "}" +
            "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        // pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"rsa\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });
  }

  private void checkEntity(String expectedPublicKey, String expectedPrivateKey, String actualPublicKey, String actualPrivateKey) {
    String requestJson = createJson(actualPublicKey, actualPrivateKey);
    DocumentContext parsed = jsonPath.parse(requestJson);
    subject.populateEntityFromJson(entity, parsed);
    assertThat(entity.getPublicKey(), equalTo(expectedPublicKey));
    assertThat(entity.getPrivateKey(), equalTo(expectedPrivateKey));
  }

  private String createJson(String publicKey, String privateKey) {
    return "{\"type\":\"rsa\",\"value\":{\"public_key\":\"" + publicKey + "\",\"private_key\":\"" + privateKey + "\"}}";
  }
}
