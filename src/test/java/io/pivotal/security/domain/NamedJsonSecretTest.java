package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedJsonSecretData;
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
public class NamedJsonSecretTest {

  private Encryptor encryptor;

  private NamedJsonSecret subject;
  private Map<String, Object> value;
  private UUID canaryUuid;

  private NamedJsonSecretData namedJsonSecretData;

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

      namedJsonSecretData = new NamedJsonSecretData("Foo");
      subject = new NamedJsonSecret(namedJsonSecretData);
    });

    it("returns type value", () -> {
      assertThat(subject.getSecretType(), equalTo("json"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedJsonSecret(namedJsonSecretData).setEncryptor(encryptor);
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setValue(value);
        assertThat(namedJsonSecretData.getEncryptedValue(), notNullValue());
        assertThat(namedJsonSecretData.getNonce(), notNullValue());
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

    describe(".createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        when(encryptor.encrypt("new value"))
            .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("new value");

        subject = new NamedJsonSecret("/existingName");
        subject.setEncryptor(encryptor);
        namedJsonSecretData.setEncryptedValue("old encrypted value".getBytes());
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

        NamedJsonSecret newSecret = NamedJsonSecret
            .createNewVersion(subject, "anything I AM IGNORED", newValue, encryptor,
                new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getValue(), equalTo(newValue));
      });

      it("creates new if no existing", () -> {
        NamedJsonSecret newSecret = NamedJsonSecret.createNewVersion(
            null,
            "/newName",
            value,
            encryptor,
            new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getValue(), equalTo(value));
      });
    });
  }
}
