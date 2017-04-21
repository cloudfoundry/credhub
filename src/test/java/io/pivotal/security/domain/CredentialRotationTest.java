package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.entity.CredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
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
public class CredentialRotationTest {

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
        encryptor = new Encryptor(encryptionService);

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

        when(encryptionService.decrypt(new Encryption(oldEncryptionKeyUuid, "old-encrypted-value".getBytes(), "old-nonce".getBytes())))
            .thenReturn("plaintext");
        when(encryptionService.encrypt("plaintext"))
            .thenReturn(new Encryption(activeEncryptionKeyUuid, "new-encrypted-value".getBytes(),
                "new-nonce".getBytes()));
      });

      describe("when the credential contains an encrypted value", () -> {
        describe("when the credential is a Certificate", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            CertificateCredentialData certificateCredentialData =
                new CertificateCredentialData("some-name");
            CertificateCredential credential = new CertificateCredential(certificateCredentialData);
            assertRotation(credential, certificateCredentialData);
          });
        });

        describe("when the credential is a SSH key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            SshCredentialData sshCredentialData = new SshCredentialData("ssh-key");
            SshCredential credential = new SshCredential(sshCredentialData);
            assertRotation(credential, sshCredentialData);
          });
        });

        describe("when the credential is a RSA key", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            RsaCredentialData rsaCredentialData = new RsaCredentialData("rsa key");
            RsaCredential credential = new RsaCredential(rsaCredentialData);
            assertRotation(credential, rsaCredentialData);
          });
        });

        describe("when the credential is a value credential", () -> {
          it("should re-encrypt with the active encryption key", () -> {
            ValueCredentialData valueCredentialData = new ValueCredentialData("value key");
            ValueCredential credential = new ValueCredential(valueCredentialData);
            assertRotation(credential, valueCredentialData);
          });
        });

        describe("when the credential is a PasswordCredentialData", () -> {
          it("should re-encrypt the password and the parameters with the active encryption key",
              () -> {
            PasswordCredentialData passwordCredentialData =
                new PasswordCredentialData("some-name");
            passwordCredentialData.setEncryptionKeyUuid(oldEncryptionKeyUuid);
            passwordCredentialData.setEncryptedValue("old-encrypted-value".getBytes());
            passwordCredentialData.setNonce("old-nonce".getBytes());
            PasswordCredential password = new PasswordCredential(passwordCredentialData);
            password.setEncryptor(encryptor);

            passwordCredentialData.setEncryptedGenerationParameters("old-encrypted-parameters".getBytes());
            passwordCredentialData.setParametersNonce("old-parameters-nonce".getBytes());

            stringifiedParameters = new ObjectMapper()
                .writeValueAsString(new StringGenerationParameters());

            when(encryptionService
                .decrypt(new Encryption(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes())))
                .thenReturn(stringifiedParameters);
            when(encryptionService.encrypt(stringifiedParameters))
                .thenReturn(new Encryption(activeEncryptionKeyUuid,
                    "new-encrypted-parameters".getBytes(), "new-nonce-parameters".getBytes()));

            password.rotate();
            assertThat(passwordCredentialData.getEncryptionKeyUuid(),
                equalTo(activeEncryptionKeyUuid));
            assertThat(passwordCredentialData.getEncryptedValue(),
                equalTo("new-encrypted-value".getBytes()));
            assertThat(passwordCredentialData.getNonce(), equalTo("new-nonce".getBytes()));

            assertThat(passwordCredentialData.getEncryptedGenerationParameters(),
                equalTo("new-encrypted-parameters".getBytes()));
            assertThat(passwordCredentialData.getParametersNonce(),
                equalTo("new-nonce-parameters".getBytes()));
          });
        });
      });
    });
  }


  private void assertRotation(Credential credential, CredentialData delegate) {
    credential.setEncryptor(encryptor);
    delegate.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    delegate.setEncryptedValue("old-encrypted-value".getBytes());
    delegate.setNonce("old-nonce".getBytes());

    credential.rotate();

    assertThat(delegate.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(delegate.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
    assertThat(delegate.getNonce(), equalTo("new-nonce".getBytes()));
  }
}
