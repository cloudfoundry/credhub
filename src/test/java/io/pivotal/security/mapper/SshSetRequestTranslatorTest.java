package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SshSetRequestTranslatorTest {
  private ParseContext jsonPath;
  private NamedSshSecret entity;
  private Encryptor encryptor;
  private SshSetRequestTranslator subject;

  {
    beforeEach(() -> {
      jsonPath = new JsonContextFactory().getObject();
    });

    describe("populating entity from json", () -> {
      beforeEach(() -> {
        encryptor = mock(Encryptor.class);
        byte[] encryptedValue = "fake-encrypted-value".getBytes();
        byte[] nonce = "fake-nonce".getBytes();
        when(encryptor.encrypt("my-private-key")).thenReturn(new Encryption(encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("my-private-key");

        byte[] encryptedEmptyString = "encrypted-empty-string".getBytes();
        byte[] emptyStringNonce = "empty-string-nonce".getBytes();
        when(encryptor.encrypt(null)).thenReturn(new Encryption(encryptedEmptyString, emptyStringNonce));
        when(encryptor.encrypt("")).thenReturn(new Encryption(encryptedEmptyString, emptyStringNonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedEmptyString), eq(emptyStringNonce))).thenReturn(null);

        subject = new SshSetRequestTranslator();
        entity = new NamedSshSecret("Foo");
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
            "\"type\":\"Ssh\"," +
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
        String requestBody = "{\"type\":\"Ssh\",\"foo\":\"invalid\"}";
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
    return "{\"type\":\"Ssh\",\"value\":{\"public_key\":\"" + publicKey + "\",\"private_key\":\"" + privateKey + "\"}}";
  }
}
