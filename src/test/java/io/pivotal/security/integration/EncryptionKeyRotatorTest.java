package io.pivotal.security.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.EncryptionKeyRotator;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static java.util.Collections.singletonList;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNot.not;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {
  private NamedSecret secretWithCurrentKey;
  private NamedSecret secretWithOldKey;
  private NamedSecret secretWithUnknownKey;

  @SpyBean
  SecretDataService secretDataService;

  @SpyBean
  SecretEncryptionHelper encryptionHelper;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  EncryptionService encryptionService;
  private EncryptionKeyCanary unknownCanary;
  private EncryptionKeyCanary oldCanary;

  private String passwordName;

  {
    wireAndUnwire(this, false);

    describe("when data exists that is encrypted with an unknown key", () -> {
      beforeEach(() -> {
        secretWithCurrentKey = new NamedCertificateSecret("cert");
        encryptionHelper.refreshEncryptedValue(secretWithCurrentKey, "cert-private-key");
        secretDataService.save(secretWithCurrentKey);

        Key oldKey = new SecretKeySpec(parseHexBinary("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0, 16, "AES");
        oldCanary = new EncryptionKeyCanary();
        final Encryption canaryEncryption = encryptionService.encrypt(oldKey, CANARY_VALUE);
        oldCanary.setEncryptedValue(canaryEncryption.encryptedValue);
        oldCanary.setNonce(canaryEncryption.nonce);
        oldCanary = encryptionKeyCanaryDataService.save(oldCanary);
        when(encryptionKeyCanaryMapper.getKeyForUuid(oldCanary.getUuid())).thenReturn(oldKey);
        when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys()).thenReturn(singletonList(oldCanary.getUuid()));

        secretWithOldKey = new NamedCertificateSecret("cert");
        final Encryption encryption = encryptionService.encrypt(oldKey, "old-certificate-private-key");
        secretWithOldKey.setEncryptedValue(encryption.encryptedValue);
        secretWithOldKey.setNonce(encryption.nonce);
        secretWithOldKey.setEncryptionKeyUuid(oldCanary.getUuid());
        secretDataService.save(secretWithOldKey);

        unknownCanary = new EncryptionKeyCanary();
        unknownCanary.setEncryptedValue("bad-encrypted-value".getBytes());
        unknownCanary.setNonce("bad-nonce".getBytes());
        unknownCanary = encryptionKeyCanaryDataService.save(unknownCanary);

        secretWithUnknownKey = new NamedCertificateSecret("cert");
        encryptionHelper.refreshEncryptedValue(secretWithUnknownKey, "cert-private-key");
        secretWithUnknownKey.setEncryptionKeyUuid(unknownCanary.getUuid());
        secretDataService.save(secretWithUnknownKey);

        passwordName = "/test-password";
        NamedPasswordSecret password = new NamedPasswordSecret(passwordName);
        final Encryption secretEncryption = encryptionService.encrypt(oldKey, "test-password-plaintext");
        password.setEncryptedValue(secretEncryption.encryptedValue);
        password.setNonce(secretEncryption.nonce);
        PasswordGenerationParameters parameters = new PasswordGenerationParameters();
        parameters.setExcludeNumber(true);
        final Encryption parameterEncryption = encryptionService.encrypt(oldKey, new ObjectMapper().writeValueAsString(parameters));
        password.setEncryptedGenerationParameters(parameterEncryption.encryptedValue);
        password.setParametersNonce(parameterEncryption.nonce);
        password.setEncryptionKeyUuid(oldCanary.getUuid());

        secretDataService.save(password);
      });

      afterEach(() -> {
        secretDataService.delete("cert");
        encryptionKeyCanaryDataService.delete(oldCanary);
        encryptionKeyCanaryDataService.delete(unknownCanary);
      });

      it("should rotate data that it can decrypt (and it shouldn't loop forever!)", () -> {
        encryptionKeyRotator.rotate();

        ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);
        verify(encryptionHelper, times(2)).rotate(argumentCaptor.capture());
        List<NamedSecret> namedSecrets = argumentCaptor.getAllValues();
        List<UUID> uuids = namedSecrets.stream().map(secret -> secret.getUuid()).collect(Collectors.toList());

        // Get's updated to use current key:
        assertThat(secretDataService.findByUuid(secretWithOldKey.getUuid()).getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
        assertThat(uuids, hasItem(secretWithOldKey.getUuid()));

        // Unchanged because we don't have the key:
        assertThat(secretDataService.findByUuid(secretWithUnknownKey.getUuid()).getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));
        assertThat(uuids, not(hasItem(secretWithUnknownKey.getUuid())));

        // Unchanged because it's already up to date:
        assertThat(secretDataService.findByUuid(secretWithCurrentKey.getUuid()).getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
        assertThat(uuids, not(hasItem(secretWithCurrentKey.getUuid())));

        NamedPasswordSecret rotatedPassword = (NamedPasswordSecret) secretDataService.findMostRecent(passwordName);
        assertThat(rotatedPassword.getPassword(), equalTo("test-password-plaintext"));
        assertThat(rotatedPassword.getGenerationParameters(), samePropertyValuesAs(
          new PasswordGenerationParameters()
            .setExcludeNumber(true)
            .setLength(23))
        );
      });
    });

  }
}
