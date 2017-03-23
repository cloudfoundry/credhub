package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class NamedPasswordSecretTest {
  private static List<AccessControlEntry> NO_ENTRIES_PROVIDED = new ArrayList<>();

  private Encryptor encryptor;
  private NamedPasswordSecret subject;
  private PasswordGenerationParameters generationParameters;
  private UUID canaryUUID;

  {
    beforeEach(() -> {
      canaryUUID = UUID.randomUUID();
      generationParameters = new PasswordGenerationParameters();
      generationParameters.setExcludeLower(true);
      generationParameters.setIncludeSpecial(false);
      generationParameters.setLength(10);

      encryptor = mock(Encryptor.class);

      when(encryptor.encrypt(null)).thenReturn(new Encryption(canaryUUID, null, null));

      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();
      when(encryptor.encrypt("my-value")).thenReturn(new Encryption(canaryUUID, encryptedValue, nonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("my-value");

      String generationParametersJson = new ObjectMapper().writeValueAsString(generationParameters);
      byte[] encryptedParametersValue = "fake-encrypted-parameters".getBytes();
      byte[] parametersNonce = "fake-parameters-nonce".getBytes();
      when(encryptor.encrypt(generationParametersJson))
          .thenReturn(new Encryption(canaryUUID, encryptedParametersValue, parametersNonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedParametersValue), eq(parametersNonce)))
          .thenReturn(generationParametersJson);

      subject = new NamedPasswordSecret("/Foo");
      subject.setEncryptor(encryptor);

    });

    it("returns type password", () -> {
      assertThat(subject.getSecretType(), equalTo("password"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedPasswordSecret("/foo");
        subject.setEncryptor(encryptor);
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setPasswordAndGenerationParameters("my-value", null);
        assertThat(subject.getEncryptedValue(), notNullValue());
        assertThat(subject.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setPasswordAndGenerationParameters("my-value", generationParameters);

        assertThat(subject.getPassword(), equalTo("my-value"));

        assertThat(subject.getGenerationParameters().getLength(), equalTo(8));
        assertThat(subject.getGenerationParameters().isExcludeLower(), equalTo(true));
        assertThat(subject.getGenerationParameters().isExcludeUpper(), equalTo(false));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setPasswordAndGenerationParameters(null, null);
      });

      it("sets the parametersNonce and the encryptedGenerationParameters", () -> {
        subject.setPasswordAndGenerationParameters("my-value", generationParameters);
        assertThat(subject.getEncryptedGenerationParameters(), notNullValue());
        assertThat(subject.getParametersNonce(), notNullValue());
      });

      it("should set encrypted generation parameters and nonce to null if parameters are null", () -> {
        subject = new NamedPasswordSecret("password-with-null-parameters");
        subject.setEncryptor(encryptor);
        subject.setPasswordAndGenerationParameters("my-value", null);
        assertThat(subject.getEncryptedGenerationParameters(), nullValue());
        assertThat(subject.getParametersNonce(), nullValue());
      });
    });

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();

        PasswordGenerationParameters parameters = new PasswordGenerationParameters();
        parameters.setExcludeNumber(true);
        parameters.setExcludeLower(true);
        parameters.setExcludeUpper(false);

        String generationParametersJson = new ObjectMapper().writeValueAsString(parameters);
        byte[] encryptedParametersValue = "fake-encrypted-parameters".getBytes();
        byte[] parametersNonce = "fake-parameters-nonce".getBytes();
        when(encryptor.encrypt(generationParametersJson))
            .thenReturn(new Encryption(canaryUUID, encryptedParametersValue, parametersNonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedParametersValue), eq(parametersNonce)))
            .thenReturn(generationParametersJson);

        subject = new NamedPasswordSecret("/foo");
        subject.setEncryptor(encryptor);
        subject.setPasswordAndGenerationParameters("my-value", parameters);
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);

        byte[] initialEncryptedValue = subject.getEncryptedValue();
        byte[] initialNonce = subject.getParametersNonce();
        UUID encryptionKeuUuid = subject.getEncryptionKeyUuid();

        NamedPasswordSecret copy = new NamedPasswordSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/foo"));
        assertThat(copy.getPassword(), equalTo("my-value"));
        assertThat(copy.getEncryptedValue(), equalTo(initialEncryptedValue));

        assertThat(subject.getGenerationParameters(), samePropertyValuesAs(copy.getGenerationParameters()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeuUuid));
        assertThat(copy.getParametersNonce(), equalTo(initialNonce));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });

    describe(".createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        when(encryptor.encrypt("new password")).thenReturn(new Encryption(canaryUUID, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("new password");

        subject = new NamedPasswordSecret("/existingName");
        subject.setEncryptor(encryptor);
        subject.setEncryptedValue("old encrypted value".getBytes());
      });

      it("copies values from existing, except password", () -> {
        NamedPasswordSecret newSecret = NamedPasswordSecret.createNewVersion(subject, "anything I AM IGNORED", "new password", encryptor, NO_ENTRIES_PROVIDED);

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getPassword(), equalTo("new password"));
      });

      it("creates new if no existing", () -> {
        NamedPasswordSecret newSecret = NamedPasswordSecret.createNewVersion(
            null,
            "/newName",
            "new password",
            encryptor,
            NO_ENTRIES_PROVIDED);

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getPassword(), equalTo("new password"));
      });
    });
  }
}
