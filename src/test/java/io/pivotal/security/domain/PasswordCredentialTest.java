package io.pivotal.security.domain;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class PasswordCredentialTest {

  private static final List<AccessControlEntry> EMPTY_ENTRIES_LIST = new ArrayList<>();
  private static final StringGenerationParameters NO_PASSWORD_PARAMS = null;
  private static final PasswordCredential NO_EXISTING_NAMED_PASSWORD_CREDENTIAL = null;
  private static final List<AccessControlEntry> NULL_ENTRIES_LIST = null;
  private static final String PASSWORD = "my-password";

  private PasswordCredential subject;
  private PasswordCredentialData passwordCredentialData;
  private Encryptor encryptor;
  private UUID canaryUuid;
  private StringGenerationParameters generationParameters;

  private byte[] encryptedValue;
  private byte[] nonce;
  private byte[] encryptedParametersValue;
  private byte[] parametersNonce;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);

      encryptedValue = "fake-encrypted-value".getBytes();
      nonce = "fake-nonce".getBytes();
      encryptedParametersValue = "fake-encrypted-parameters".getBytes();
      parametersNonce = "fake-parameters-nonce".getBytes();

      generationParameters = new StringGenerationParameters()
          .setExcludeLower(true)
          .setLength(10);
      String generationParametersJson = new ObjectMapper().writeValueAsString(generationParameters);

      when(encryptor.encrypt(null))
          .thenReturn(new Encryption(canaryUuid, null, null));
      final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
      when(encryptor.encrypt(PASSWORD))
          .thenReturn(encryption);
      final Encryption parametersEncryption = new Encryption(canaryUuid, encryptedParametersValue, parametersNonce);
      when(encryptor.encrypt(eq(generationParametersJson)))
          .thenReturn(parametersEncryption);

      when(encryptor.decrypt(encryption))
          .thenReturn(PASSWORD);
      when(encryptor.decrypt(parametersEncryption))
          .thenReturn(generationParametersJson);

      passwordCredentialData = new PasswordCredentialData("/Foo");
      subject = new PasswordCredential(passwordCredentialData);
      subject.setEncryptor(encryptor);
    });

    it("returns type password", () -> {
      assertThat(subject.getCredentialType(), equalTo("password"));
    });

    describe("#getGenerationParameters", () -> {
      beforeEach(() -> {
        subject.setPasswordAndGenerationParameters(PASSWORD, null);
        subject.getPassword();
      });

      it("should call decrypt twice: once for password and once for parameters", () -> {
        subject.getGenerationParameters();

        verify(encryptor, times(2)).decrypt(any());
      });
    });

    describe("#getPassword", () -> {
      beforeEach(() -> {
        subject = new PasswordCredential("/Foo");
        subject.setEncryptor(encryptor);
        when(encryptor.encrypt(null))
            .thenReturn(new Encryption(canaryUuid, null, null));
        subject.setPasswordAndGenerationParameters(PASSWORD, null);
        subject.getGenerationParameters();
      });

      it("should call decrypt twice: once for password and once for parameters", () -> {
        subject.getPassword();

        verify(encryptor, times(2)).decrypt(any());
      });
    });

    describe("#setPasswordAndGenerationParameters", () -> {
      it("sets the nonce and the encrypted value", () -> {
        subject.setPasswordAndGenerationParameters(PASSWORD, null);
        assertThat(passwordCredentialData.getEncryptedValue(), notNullValue());
        assertThat(passwordCredentialData.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setPasswordAndGenerationParameters(PASSWORD, generationParameters);

        assertThat(subject.getPassword(), equalTo(PASSWORD));

        assertThat(subject.getGenerationParameters().getLength(), equalTo(11));
        assertThat(subject.getGenerationParameters().isExcludeLower(), equalTo(true));
        assertThat(subject.getGenerationParameters().isExcludeUpper(), equalTo(false));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setPasswordAndGenerationParameters(null, null);
      });

      it("sets the parametersNonce and the encryptedGenerationParameters", () -> {
        subject.setPasswordAndGenerationParameters(PASSWORD, generationParameters);
        assertThat(passwordCredentialData.getEncryptedGenerationParameters(), notNullValue());
        assertThat(passwordCredentialData.getParametersNonce(), notNullValue());
      });

      it("should set encrypted generation parameters and nonce to null if parameters are null",
          () -> {
            subject.setPasswordAndGenerationParameters(PASSWORD, null);
            assertThat(passwordCredentialData.getEncryptedGenerationParameters(), nullValue());
            assertThat(passwordCredentialData.getParametersNonce(), nullValue());
          });
    });

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        passwordCredentialData = new PasswordCredentialData("/existingName");
        passwordCredentialData.setEncryptedValue("old-encrypted-value".getBytes());
        passwordCredentialData.setNonce("old-nonce".getBytes());
        passwordCredentialData
            .setEncryptedGenerationParameters("old-encrypted-parameters".getBytes());
        passwordCredentialData.setParametersNonce("old-parameters-nonce".getBytes());
        subject = new PasswordCredential(passwordCredentialData);
        subject.setEncryptor(encryptor);

        ArrayList<AccessControlOperation> operations = newArrayList(AccessControlOperation.READ,
            AccessControlOperation.WRITE);
        List<AccessControlEntry> accessControlEntries = newArrayList(
            new AccessControlEntry("Bob", operations));
      });

      it("copies values from existing, except password", () -> {
        PasswordCredential newCredential = PasswordCredential
            .createNewVersion(subject, "anything I AM IGNORED", PASSWORD, NO_PASSWORD_PARAMS, encryptor);

        assertThat(newCredential.getName(), equalTo("/existingName"));
        assertThat(newCredential.getPassword(), equalTo(PASSWORD));
      });

      it("creates new if no existing", () -> {
        PasswordCredential newCredential = PasswordCredential.createNewVersion(
            NO_EXISTING_NAMED_PASSWORD_CREDENTIAL,
            "/newName",
            PASSWORD,
            NO_PASSWORD_PARAMS,
            encryptor
        );

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getPassword(), equalTo(PASSWORD));
      });
    });
  }
}
