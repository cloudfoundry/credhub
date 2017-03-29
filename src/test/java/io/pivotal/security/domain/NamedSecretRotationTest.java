package io.pivotal.security.domain;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import java.security.Key;
import java.util.UUID;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class NamedSecretRotationTest {

  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private Key activeEncryptionKey;

  private Key oldEncryptionKey;

  private UUID activeEncryptionKeyUuid;
  private UUID oldEncryptionKeyUuid;

  private String stringifiedParameters;

  private RetryingEncryptionService encryptionService;
  private Encryptor encryptor;

  {
    describe("#rotate", () -> {
      beforeEach(() -> {
        encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
        encryptionService = mock(RetryingEncryptionService.class);
        encryptor = new Encryptor(encryptionKeyCanaryMapper, encryptionService);

        activeEncryptionKey = mock(Key.class);
        oldEncryptionKey = mock(Key.class);

        oldEncryptionKeyUuid = UUID.randomUUID();
        activeEncryptionKeyUuid = UUID.randomUUID();

        when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeEncryptionKeyUuid);
        when(encryptionKeyCanaryMapper.getActiveKey()).thenReturn(activeEncryptionKey);
        when(encryptionKeyCanaryMapper.getKeyForUuid(activeEncryptionKeyUuid))
            .thenReturn(activeEncryptionKey);
        when(encryptionKeyCanaryMapper.getKeyForUuid(oldEncryptionKeyUuid))
            .thenReturn(oldEncryptionKey);

        when(encryptionService.decrypt(oldEncryptionKeyUuid, "old-encrypted-value".getBytes(),
            "old-nonce".getBytes()))
            .thenReturn("plaintext");
        when(encryptionService.encrypt(activeEncryptionKeyUuid, "plaintext"))
            .thenReturn(new Encryption(activeEncryptionKeyUuid, "new-encrypted-value".getBytes(),
                "new-nonce".getBytes()));
      });

      describe("when the secret contains an encrypted value", () -> {
        describe("when the secret is a Certificate", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedCertificateSecret secret = new NamedCertificateSecret("some-name");
            assertRotation(secret);
          });
        });

        describe("when the secret is a SSH key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedSshSecret secret = new NamedSshSecret("ssh key");
            assertRotation(secret);
          });
        });

        describe("when the secret is a RSA key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedRsaSecret secret = new NamedRsaSecret("ssh key");
            assertRotation(secret);
          });
        });

        describe("when the secret is a value secret", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedValueSecret secret = new NamedValueSecret("ssh key");
            assertRotation(secret);
          });
        });

        describe("when the secret is a value secret", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedValueSecret secret = new NamedValueSecret("ssh key");
            assertRotation(secret);
          });
        });

        describe("when the secret is a NamedPasswordSecretData", () -> {
          it("should re-encrypt the password and the parameters with the active encryption key",
              () -> {
                NamedPasswordSecret password = new NamedPasswordSecret("some-name");
                password.setEncryptor(encryptor);
                password.setEncryptionKeyUuid(oldEncryptionKeyUuid);
                password.setEncryptedValue("old-encrypted-value".getBytes());
                password.setNonce("old-nonce".getBytes());

                password.setEncryptedGenerationParameters("old-encrypted-parameters".getBytes());
                password.setParametersNonce("old-parameters-nonce".getBytes());

                stringifiedParameters = new ObjectMapper()
                    .writeValueAsString(new PasswordGenerationParameters());

                when(encryptionService
                    .decrypt(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(),
                        "old-parameters-nonce".getBytes()))
                    .thenReturn(stringifiedParameters);
                when(encryptionService.encrypt(activeEncryptionKeyUuid, stringifiedParameters))
                    .thenReturn(new Encryption(activeEncryptionKeyUuid,
                        "new-encrypted-parameters".getBytes(), "new-nonce-parameters".getBytes()));

                password.rotate();
                assertThat(password.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
                assertThat(password.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
                assertThat(password.getNonce(), equalTo("new-nonce".getBytes()));

                assertThat(password.getEncryptedGenerationParameters(),
                    equalTo("new-encrypted-parameters".getBytes()));
                assertThat(password.getParametersNonce(),
                    equalTo("new-nonce-parameters".getBytes()));
              });
        });
      });
    });
  }


  private void assertRotation(NamedSecret secret) {
    secret.setEncryptor(encryptor);
    secret.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    secret.setEncryptedValue("old-encrypted-value".getBytes());
    secret.setNonce("old-nonce".getBytes());

    secret.rotate();

    assertThat(secret.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(secret.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
    assertThat(secret.getNonce(), equalTo("new-nonce".getBytes()));
  }
}
