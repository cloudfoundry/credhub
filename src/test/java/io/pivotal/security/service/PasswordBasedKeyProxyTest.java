package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.bouncycastle.util.encoders.Hex;
import org.junit.runner.RunWith;

import java.security.Key;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.EncryptionConstants.SALT_SIZE;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Spectrum.class)
public class PasswordBasedKeyProxyTest {
  private PasswordBasedKeyProxy subject;
  private String password;

  private BCEncryptionService encryptionService;
  private Key derivedKey;
  private EncryptionKeyCanary canary;

  {
    beforeEach(() -> {
      password = "abcdefghijklmnopqrst";
      encryptionService = new BCEncryptionService();
      subject = new PasswordBasedKeyProxy(password, encryptionService);
    });

    describe("#deriveKey", () -> {
      it("returns the expected Key", () -> {
        final String knownRandomNumber = "7034522dc85138530e44b38d0569ca67";
        final String knownGeneratedKey = "23e48f2bafa327a174a46400063cd9e6";
        byte[] salt = Hex.decode(knownRandomNumber); // gen'd originally from SecureRandom..
        String hexOutput = Hex.toHexString(subject.deriveKey(password, salt).getEncoded());

        assertThat(hexOutput, equalTo(knownGeneratedKey));
      });
    });

    describe("#matchesCanary", () -> {
      describe("when canary matches", () -> {
        beforeEach(() -> {
          PasswordBasedKeyProxy oldProxy = new PasswordBasedKeyProxy(password, encryptionService);
          final byte[] salt = oldProxy.generateSalt();
          derivedKey = oldProxy.deriveKey(password, salt);
          final Encryption encryptedCanary = encryptionService.encrypt(derivedKey, CANARY_VALUE);
          canary = new EncryptionKeyCanary();
          canary.setEncryptedValue(encryptedCanary.encryptedValue);
          canary.setNonce(encryptedCanary.nonce);
          canary.setSalt(salt);
        });

        it("sets the key", () -> {
          final boolean match = subject.matchesCanary(canary);
          assertTrue(match);
          assertThat(subject.getKey(), equalTo(derivedKey));
        });
      });
      describe("when canary does not match", () -> {
        it("does not affect the key", () -> {
          canary = new EncryptionKeyCanary();
          canary.setSalt(new byte[SALT_SIZE]);
          canary.setNonce(new byte[NONCE_SIZE]);
          canary.setEncryptedValue(new byte[32]);
          final boolean match = subject.matchesCanary(canary);
          assertFalse(match);
          assertThat(subject.getKey(), not(equalTo(derivedKey)));
        });
      });
    });

    describe("#getKey", () -> {
      describe("when no key has been set", () -> {
        it("derives a new key and salt", () -> {
          subject = new PasswordBasedKeyProxy("some password", encryptionService);
          assertThat(subject.getSalt(), equalTo(null));

          assertThat(subject.getKey(), not(equalTo(null)));
          assertThat(subject.getSalt(), not(equalTo(null)));
        });
      });
    });
  }
}
