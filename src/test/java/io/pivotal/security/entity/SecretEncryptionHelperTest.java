package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.service.Encryption;
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

@RunWith(Spectrum.class)
public class SecretEncryptionHelperTest {

  private SecretEncryptionHelper subject;
  private EncryptionService encryptionService;

  private PasswordGenerationParameters passwordGenerationParameters;

  private String stringifiedParameters;

  {
    beforeEach(() -> {
      encryptionService = mock(EncryptionService.class);
      subject = new SecretEncryptionHelper(encryptionService);
    });

    describe("#refreshEncryptedValue", () -> {
      beforeEach(() -> {
        when(encryptionService.encrypt("fake-plaintext"))
            .thenReturn(new Encryption("some-encrypted-value".getBytes(), "some-nonce".getBytes()));
      });

      describe("when there is no plaintext value", () -> {
        it("should not encrypt the value", () -> {
          NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
          subject.refreshEncryptedValue(valueContainer, null);
          assertThat(valueContainer.getEncryptedValue(), equalTo(null));
          assertThat(valueContainer.getNonce(), equalTo(null));
        });
      });

      describe("when there is a plaintext value", () -> {
        it("encrypts the value and updates the EncryptedValueContainer", () -> {
          NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

          subject.refreshEncryptedValue(valueContainer, "fake-plaintext");

          assertThat(valueContainer.getEncryptedValue(), equalTo("some-encrypted-value".getBytes()));
          assertThat(valueContainer.getNonce(), equalTo("some-nonce".getBytes()));
        });

        describe("when given the same plaintext value that is already used", () -> {
          it("should only encrypt the plaintext once", () -> {
            when(
                encryptionService.decrypt(
                    "fake-encrypted-value".getBytes(),
                    "fake-nonce".getBytes()
                )
            ).thenReturn("fake-plaintext");

            NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
            valueContainer.setEncryptedGenerationParameters("fake-encrypted-value".getBytes());
            valueContainer.setParametersNonce("fake-nonce".getBytes());

            subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

            verify(encryptionService, times(0)).encrypt(any(String.class));
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
          when(encryptionService.decrypt("fake-encrypted-value".getBytes(), "fake-nonce".getBytes()))
              .thenReturn("fake-plaintext-value");
        });

        it("should return the plaintext value", () -> {
          NamedCertificateSecret secret = new NamedCertificateSecret("some-name");
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

        when(encryptionService.encrypt(stringifiedParameters))
            .thenReturn(new Encryption("parameters-encrypted-value".getBytes(), "parameters-nonce".getBytes()));
      });

      describe("when there are no parameters", () -> {
        it("should not encrypt the parameters", () -> {
          NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
          subject.refreshEncryptedGenerationParameters(valueContainer, null);
          assertThat(valueContainer.getEncryptedGenerationParameters(), equalTo(null));
          assertThat(valueContainer.getParametersNonce(), equalTo(null));
        });
      });

      describe("when there are parameters", () -> {
        it("should encrypt the parameters updates the NamedPasswordSecret", () -> {
          NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");

          subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

          assertThat(valueContainer.getEncryptedGenerationParameters(), equalTo("parameters-encrypted-value".getBytes()));
          assertThat(valueContainer.getParametersNonce(), equalTo("parameters-nonce".getBytes()));
        });

        describe("when given the same plaintext value that is already used", () -> {
          it("should only encrypt the parameters once", () -> {
            when(
                encryptionService.decrypt(
                    "parameters-encrypted-value".getBytes(),
                    "parameters-nonce".getBytes()
                )
            ).thenReturn(stringifiedParameters);

            NamedPasswordSecret valueContainer = new NamedPasswordSecret("my-password");
            valueContainer.setEncryptedGenerationParameters("parameters-encrypted-value".getBytes());
            valueContainer.setParametersNonce("parameters-nonce".getBytes());

            subject.refreshEncryptedGenerationParameters(valueContainer, passwordGenerationParameters);

            verify(encryptionService, times(0)).encrypt(any(String.class));
          });
        });
      });
    });
  }
}
