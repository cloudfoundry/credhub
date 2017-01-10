package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKey;
import io.pivotal.security.service.EncryptionKeyService;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

@RunWith(Spectrum.class)
public class SecretEncryptionHelperTest {

  private SecretEncryptionHelper subject;
  private EncryptionKeyService encryptionKeyService;
  private EncryptionService encryptionService;
  private EncryptionKey activeEncryptionKey;

  private EncryptionKey oldEncryptionKey;

  private UUID activeEncryptionKeyUuid;
  private UUID oldEncryptionKeyUuid;
  private PasswordGenerationParameters passwordGenerationParameters;

  private String stringifiedParameters;

  {
    beforeEach(() -> {
      encryptionService = mock(EncryptionService.class);
      encryptionKeyService = mock(EncryptionKeyService.class);
      subject = new SecretEncryptionHelper(encryptionKeyService, encryptionService);

      activeEncryptionKey = mock(EncryptionKey.class);
      oldEncryptionKey = mock(EncryptionKey.class);

      oldEncryptionKeyUuid = UUID.randomUUID();
      activeEncryptionKeyUuid = UUID.randomUUID();

      when(encryptionKeyService.getActiveEncryptionKeyUuid()).thenReturn(activeEncryptionKeyUuid);
      when(encryptionKeyService.getActiveEncryptionKey()).thenReturn(activeEncryptionKey);
      when(encryptionKeyService.getEncryptionKey(activeEncryptionKeyUuid)).thenReturn(activeEncryptionKey);
      when(encryptionKeyService.getEncryptionKey(oldEncryptionKeyUuid)).thenReturn(oldEncryptionKey);
    });

    describe("#refreshEncryptedValue", () -> {
      beforeEach(() -> {
        when(encryptionService.encrypt(activeEncryptionKey, "fake-plaintext"))
            .thenReturn(new Encryption("some-encrypted-value".getBytes(), "some-nonce".getBytes()));
      });

      describe("when there is no plaintext value", () -> {
        it("should only set the encryption key", () -> {
          NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
          subject.refreshEncryptedValue(valueContainer, null);
          assertThat(valueContainer.getNonce(), equalTo(null));
          assertThat(valueContainer.getEncryptedValue(), equalTo(null));
          assertThat(valueContainer.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
        });
      });

      describe("when there is a plaintext value", () -> {
        it("encrypts the value and updates the EncryptedValueContainer", () -> {
          NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

          subject.refreshEncryptedValue(valueContainer, "fake-plaintext");

          assertThat(valueContainer.getNonce(), equalTo("some-nonce".getBytes()));
          assertThat(valueContainer.getEncryptedValue(), equalTo("some-encrypted-value".getBytes()));
          assertThat(valueContainer.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
        });

        describe("when given the same plaintext value that is already used", () -> {
          describe("when the secret was encrypted with the active encryption key", () -> {
            it("should only encrypt the value once", () -> {
              when(
                  encryptionService.decrypt(
                      activeEncryptionKey,
                      "fake-encrypted-value".getBytes(),
                      "fake-nonce".getBytes()
                  )
              ).thenReturn("fake-plaintext");

              NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
              valueContainer.setEncryptionKeyUuid(activeEncryptionKeyUuid);
              valueContainer.setEncryptedValue("fake-encrypted-value".getBytes());
              valueContainer.setNonce("fake-nonce".getBytes());

              subject.refreshEncryptedValue(valueContainer, "fake-plaintext");

              verify(encryptionService, times(0)).encrypt(any(EncryptionKey.class), any(String.class));
            });
          });

          describe("when the encryption key has changed", () -> {
            it("should re-encrypt the value with the active key", () -> {
              when(
                  encryptionService.decrypt(
                      oldEncryptionKey,
                      "fake-old-encrypted-value".getBytes(),
                      "fake-old-nonce".getBytes()
                  )
              ).thenReturn("fake-plaintext");

              NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
              valueContainer.setEncryptionKeyUuid(oldEncryptionKeyUuid);
              valueContainer.setEncryptedValue("fake-old-encrypted-value".getBytes());
              valueContainer.setNonce("fake-old-nonce".getBytes());

              subject.refreshEncryptedValue(valueContainer, "fake-plaintext");

              verify(encryptionService, times(1)).encrypt(any(EncryptionKey.class), any(String.class));
            });
          });
        });
      });
    });

    describe("#retrieveClearTextValue", () -> {
      describe("when there is no encrypted value", () -> {
        it("should return null", () -> {
          NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

          assertThat(subject.retrieveClearTextValue(valueContainer), equalTo(null));
        });
      });

      describe("when there is an encrypted value", () -> {
        beforeEach(() -> {
          when(encryptionService.decrypt(oldEncryptionKey, "fake-encrypted-value".getBytes(), "fake-nonce".getBytes()))
              .thenReturn("fake-plaintext-value");
        });

        it("should return the plaintext value", () -> {
          NamedCertificateSecret secret = new NamedCertificateSecret("some-name");
          secret.setEncryptionKeyUuid(oldEncryptionKeyUuid);
          secret.setEncryptedValue("fake-encrypted-value".getBytes());
          secret.setNonce("fake-nonce".getBytes());

          assertThat(subject.retrieveClearTextValue(secret), equalTo("fake-plaintext-value"));
        });
      });
    });

    describe("#refreshEncryptedGenerationParameters", () -> {
      beforeEach(() -> {
        passwordGenerationParameters = new PasswordGenerationParameters().setExcludeSpecial(true);
        stringifiedParameters = new ObjectMapper().writeValueAsString(passwordGenerationParameters);

        when(encryptionService.encrypt(activeEncryptionKey, stringifiedParameters))
            .thenReturn(new Encryption("parameters-encrypted-value".getBytes(), "parameters-nonce".getBytes()));
      });

      describe("when there are no password parameters", () -> {
        it("should only set the parameter encryption key", () -> {
          NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
          subject.refreshEncryptedGenerationParameters(valueContainer, null);
          assertThat(valueContainer.getEncryptedGenerationParameters(), equalTo(null));
          assertThat(valueContainer.getParametersNonce(), equalTo(null));
          assertThat(valueContainer.getParameterEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
        });
      });

      describe("when there are parameters", () -> {
        it("should encrypt the parameters updates the NamedPasswordSecret", () -> {
          NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");

          subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

          assertThat(valueContainer.getEncryptedGenerationParameters(), equalTo("parameters-encrypted-value".getBytes()));
          assertThat(valueContainer.getParametersNonce(), equalTo("parameters-nonce".getBytes()));
          assertThat(valueContainer.getParameterEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
        });

        describe("when given the same parameters that are already used", () -> {
          describe("when the parameters were encrypted with the active encryption key", () -> {
            it("should only encrypt the parameters once", () -> {
              when(
                  encryptionService.decrypt(
                      activeEncryptionKey,
                      "parameters-encrypted-value".getBytes(),
                      "parameters-nonce".getBytes()
                  )
              ).thenReturn(stringifiedParameters);

              NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
              valueContainer.setParameterEncryptionKeyUuid(activeEncryptionKeyUuid);
              valueContainer.setEncryptedGenerationParameters("parameters-encrypted-value".getBytes());
              valueContainer.setParametersNonce("parameters-nonce".getBytes());

              subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

              verify(encryptionService, times(0)).encrypt(any(EncryptionKey.class), any(String.class));
            });
          });

          describe("when the encryption key has changed", () -> {
            it("should re-encrypt the parameters with the active key", () -> {
              when(
                  encryptionService.decrypt(
                      oldEncryptionKey,
                      "parameters-old-encrypted-value".getBytes(),
                      "parameters-old-nonce".getBytes()
                  )
              ).thenReturn("parameters-plaintext");

              NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
              valueContainer.setParameterEncryptionKeyUuid(oldEncryptionKeyUuid);
              valueContainer.setEncryptedGenerationParameters("parameters-old-encrypted-value".getBytes());
              valueContainer.setNonce("parameters-old-nonce".getBytes());

              subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

              verify(encryptionService, times(1)).encrypt(any(EncryptionKey.class), any(String.class));
            });
          });
        });
      });
    });

    describe("#rotate", () -> {
      describe("when given a NamedSecret", () -> {
        it("should re-encrypt with the active encryption key", () -> {
          NamedSecret secret = new NamedCertificateSecret("some-name");
          secret.setEncryptionKeyUuid(oldEncryptionKeyUuid);
          secret.setEncryptedValue("old-encrypted-value".getBytes());
          secret.setNonce("old-nonce".getBytes());

          when(encryptionService.decrypt(oldEncryptionKey, "old-encrypted-value".getBytes(), "old-nonce".getBytes()))
              .thenReturn("plaintext");
          when(encryptionService.encrypt(activeEncryptionKey, "plaintext"))
              .thenReturn(new Encryption("new-encrypted-value".getBytes(), "new-nonce".getBytes()));

          subject.rotate(secret);

          assertThat(secret.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
          assertThat(secret.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
          assertThat(secret.getNonce(), equalTo("new-nonce".getBytes()));
        });
      });

      describe("when given a NamedPasswordSecret", () -> {
        it("should re-encrypt with the active encryption key", () -> {
          NamedPasswordSecret password = new NamedPasswordSecret("some-name");

          password.setEncryptionKeyUuid(activeEncryptionKeyUuid);
          password.setEncryptedValue("fake-encrypted-value".getBytes());
          password.setNonce("fake-nonce".getBytes());

          password.setParameterEncryptionKeyUuid(oldEncryptionKeyUuid);
          password.setEncryptedGenerationParameters("old-encrypted-parameters".getBytes());
          password.setParametersNonce("old-parameters-nonce".getBytes());

          stringifiedParameters = new ObjectMapper().writeValueAsString(new PasswordGenerationParameters());

          when(encryptionService.decrypt(activeEncryptionKey, "fake-encrypted-value".getBytes(), "fake-nonce".getBytes()))
              .thenReturn("plaintext-password");
          when(encryptionService.decrypt(oldEncryptionKey, "old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes()))
              .thenReturn(stringifiedParameters);
          when(encryptionService.encrypt(activeEncryptionKey, stringifiedParameters))
              .thenReturn(new Encryption("new-encrypted-value".getBytes(), "new-nonce".getBytes()));

          subject.rotate(password);

          assertThat(password.getParameterEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
          assertThat(password.getEncryptedGenerationParameters(), equalTo("new-encrypted-value".getBytes()));
          assertThat(password.getParametersNonce(), equalTo("new-nonce".getBytes()));
        });
      });

      describe("when given a NamedCertificateAuthority", () -> {
        it("should re-encrypt with the active encryption key", () -> {
          NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority("some-name");
          certificateAuthority.setEncryptionKeyUuid(oldEncryptionKeyUuid);
          certificateAuthority.setEncryptedValue("old-encrypted-value".getBytes());
          certificateAuthority.setNonce("old-nonce".getBytes());

          when(encryptionService.decrypt(oldEncryptionKey, "old-encrypted-value".getBytes(), "old-nonce".getBytes()))
              .thenReturn("plaintext");
          when(encryptionService.encrypt(activeEncryptionKey, "plaintext"))
              .thenReturn(new Encryption("new-encrypted-value".getBytes(), "new-nonce".getBytes()));

          subject.rotate(certificateAuthority);

          assertThat(certificateAuthority.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
          assertThat(certificateAuthority.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
          assertThat(certificateAuthority.getNonce(), equalTo("new-nonce".getBytes()));
        });
      });
    });
  }
}
