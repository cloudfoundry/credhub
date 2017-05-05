package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class JsonCredentialTest {

  private Encryptor encryptor;

  private JsonCredential subject;
  private Map<String, Object> value;
  private UUID canaryUuid;

  private JsonCredentialData jsonCredentialData;

  {
    beforeEach(() -> {
      Map<String, Object> nested = new HashMap<>();
      nested.put("key", "value");

      value = new HashMap<>();
      value.put("simple", "just-a-string");
      value.put("complex", nested);

      String serializedValue = new ObjectMapper().writeValueAsString(value);

      encryptor = mock(Encryptor.class);
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();
      canaryUuid = UUID.randomUUID();
      final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
      when(encryptor.encrypt(serializedValue))
          .thenReturn(encryption);
      when(encryptor.decrypt(encryption))
          .thenReturn(serializedValue);

      jsonCredentialData = new JsonCredentialData("Foo");
      subject = new JsonCredential(jsonCredentialData);
    });

    it("returns type value", () -> {
      assertThat(subject.getCredentialType(), equalTo("json"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new JsonCredential(jsonCredentialData).setEncryptor(encryptor);
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setValue(value);
        assertThat(jsonCredentialData.getEncryptedValue(), notNullValue());
        assertThat(jsonCredentialData.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue(value);
        assertThat(subject.getValue(), equalTo(value));
      });

      itThrowsWithMessage("when setting a value that is null",
          ParameterizedValidationException.class, "error.missing_value", () -> {
            subject.setValue(null);
          });
    });
  }
}
