package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.runner.RunWith;

import java.security.Key;
import java.util.Collections;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;
import static io.pivotal.security.constants.EncryptionConstants.SALT_SIZE;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static io.pivotal.security.service.PasswordBasedKeyProxy.generateSalt;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Spectrum.class)
public class PasswordBasedKeyProxyTest {

  private PasswordBasedKeyProxy subject;
  private String password;

  private BcEncryptionService encryptionService;
  private Key derivedKey;
  private EncryptionKeyCanary canary;

  {
    beforeEach(() -> {
      password = "abcdefghijklmnopqrst";
      encryptionService = new BcEncryptionService(getBouncyCastleProvider());
      subject = new PasswordBasedKeyProxy(password, encryptionService);
    });

    describe("#deriveKey", () -> {
      final String knownRandomNumber = "7034522dc85138530e44b38d0569ca67";
      final String knownGeneratedKey = "fae3e313f599e8c2327d78c1e9599102"
          + "15f19498fe2c1d199302f5c32c9790c9";

      beforeEach(() -> {
        byte[] salt = Hex.decode(knownRandomNumber); // gen'dp originally from SecureRandom..

        derivedKey = subject
            .deriveKey(Collections.unmodifiableList(asList(ArrayUtils.toObject(salt))));
      });

      it("returns the expected Key", () -> {
        String hexOutput = Hex.toHexString(derivedKey.getEncoded());

        assertThat(hexOutput, equalTo(knownGeneratedKey));
      });

      it("should derive a key that is 256 bits long", () -> {
        assertThat(derivedKey.getEncoded().length, equalTo(32));
      });
    });

    describe("#matchesCanary", () -> {
      describe("when canary matches", () -> {
        beforeEach(() -> {
          PasswordBasedKeyProxy oldProxy = new PasswordBasedKeyProxy(password, encryptionService);
          final List<Byte> salt = generateSalt();
          derivedKey = oldProxy.deriveKey(salt);
          final Encryption encryptedCanary = encryptionService
              .encrypt(null, derivedKey, CANARY_VALUE);
          canary = new EncryptionKeyCanary();
          canary.setEncryptedCanaryValue(encryptedCanary.encryptedValue);
          canary.setNonce(encryptedCanary.nonce);
          final Byte[] saltArray = new Byte[salt.size()];
          canary.setSalt(toPrimitive(salt.toArray(saltArray)));
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
          canary.setEncryptedCanaryValue(new byte[32]);
          final boolean match = subject.matchesCanary(canary);
          assertFalse(match);
          assertThat(subject.getKey(), not(equalTo(derivedKey)));
        });
      });

      describe("when canary does not contain salt", () -> {
        it("returns false for a null salt", () -> {
          canary = new EncryptionKeyCanary();
          canary.setSalt(null);
          assertFalse(subject.matchesCanary(canary));
        });

        it("returns false for an empty salt", () -> {
          canary = new EncryptionKeyCanary();
          canary.setSalt("".getBytes());
          assertFalse(subject.matchesCanary(canary));
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

    describe("#generateSalt", () -> {
      it("should minimally be the size of the hash function output", () -> {
        assertThat(generateSalt().size(), greaterThanOrEqualTo(48));
      });
    });
  }
}
