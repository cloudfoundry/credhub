package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.ArrayList;
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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
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
      when(encryptor.encrypt(serializedValue))
          .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
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

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        when(encryptor.encrypt("new value"))
            .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("new value");

        subject = new JsonCredential("/existingName");
        subject.setEncryptor(encryptor);
        jsonCredentialData.setEncryptedValue("old encrypted value".getBytes());
      });

      it("copies values from existing, except value", () -> {
        Map<String, Object> newValue = new HashMap<>();
        newValue.put("tiger", "bear");
        newValue.put("hippo", "lion");

        String serializedValue = new ObjectMapper().writeValueAsString(newValue);
        byte[] encryptedValue = "fake-new-value".getBytes();
        byte[] nonce = "fake-new-nonce".getBytes();

        when(encryptor.encrypt(serializedValue))
            .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn(serializedValue);

        JsonCredential newCredential = JsonCredential
            .createNewVersion(subject, "anything I AM IGNORED", newValue, encryptor,
                new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/existingName"));
        assertThat(newCredential.getValue(), equalTo(newValue));
      });

      it("creates new if no existing", () -> {
        JsonCredential newCredential = JsonCredential.createNewVersion(
            null,
            "/newName",
            value,
            encryptor,
            new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getValue(), equalTo(value));
      });
    });
  }
}
