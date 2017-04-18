package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.junit.runner.RunWith;

import java.security.Key;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
            NamedCertificateSecretData namedCertificateSecretData =
                new NamedCertificateSecretData("some-name");
            NamedCertificateSecret secret = new NamedCertificateSecret(namedCertificateSecretData);
            assertRotation(secret, namedCertificateSecretData);
          });
        });

        describe("when the secret is a SSH key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedSshSecretData namedSshSecretData = new NamedSshSecretData("ssh-key");
            NamedSshSecret secret = new NamedSshSecret(namedSshSecretData);
            assertRotation(secret, namedSshSecretData);
          });
        });

        describe("when the secret is a RSA key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedRsaSecretData namedRsaSecretData = new NamedRsaSecretData("rsa key");
            NamedRsaSecret secret = new NamedRsaSecret(namedRsaSecretData);
            assertRotation(secret, namedRsaSecretData);
          });
        });

        describe("when the secret is a value secret", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            NamedValueSecretData namedValueSecretData = new NamedValueSecretData("value key");
            NamedValueSecret secret = new NamedValueSecret(namedValueSecretData);
            assertRotation(secret, namedValueSecretData);
          });
        });

        describe("when the secret is a NamedPasswordSecretData", () -> {
          it("should re-encrypt the password and the parameters with the active encryption key",
              () -> {
            NamedPasswordSecretData namedPasswordSecretData =
                new NamedPasswordSecretData("some-name");
            namedPasswordSecretData.setEncryptionKeyUuid(oldEncryptionKeyUuid);
            namedPasswordSecretData.setEncryptedValue("old-encrypted-value".getBytes());
            namedPasswordSecretData.setNonce("old-nonce".getBytes());
            NamedPasswordSecret password = new NamedPasswordSecret(namedPasswordSecretData);
            password.setEncryptor(encryptor);

            namedPasswordSecretData.setEncryptedGenerationParameters("old-encrypted-parameters".getBytes());
            namedPasswordSecretData.setParametersNonce("old-parameters-nonce".getBytes());

            stringifiedParameters = new ObjectMapper()
                .writeValueAsString(new StringGenerationParameters());

            when(encryptionService
                .decrypt(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(),
                    "old-parameters-nonce".getBytes()))
                .thenReturn(stringifiedParameters);
            when(encryptionService.encrypt(activeEncryptionKeyUuid, stringifiedParameters))
                .thenReturn(new Encryption(activeEncryptionKeyUuid,
                    "new-encrypted-parameters".getBytes(), "new-nonce-parameters".getBytes()));

            password.rotate();
            assertThat(namedPasswordSecretData.getEncryptionKeyUuid(),
                equalTo(activeEncryptionKeyUuid));
            assertThat(namedPasswordSecretData.getEncryptedValue(),
                equalTo("new-encrypted-value".getBytes()));
            assertThat(namedPasswordSecretData.getNonce(), equalTo("new-nonce".getBytes()));

            assertThat(namedPasswordSecretData.getEncryptedGenerationParameters(),
                equalTo("new-encrypted-parameters".getBytes()));
            assertThat(namedPasswordSecretData.getParametersNonce(),
                equalTo("new-nonce-parameters".getBytes()));
          });
        });
      });
    });
  }


  private void assertRotation(NamedSecret secret, NamedSecretData delegate) {
    secret.setEncryptor(encryptor);
    delegate.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    delegate.setEncryptedValue("old-encrypted-value".getBytes());
    delegate.setNonce("old-nonce".getBytes());

    secret.rotate();

    assertThat(delegate.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(delegate.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
    assertThat(delegate.getNonce(), equalTo("new-nonce".getBytes()));
  }
}
