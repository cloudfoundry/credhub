package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;
import static org.cloudfoundry.credhub.constants.EncryptionConstants.KEY_BIT_LENGTH;
import static org.cloudfoundry.credhub.constants.EncryptionConstants.SALT_SIZE;

public class PasswordBasedKeyProxy extends LunaKeyProxy implements KeyProxy {

  private final SecureRandom secureRandom;
  private String password;
  private final int numIterations;
  private List<Byte> salt;

  public PasswordBasedKeyProxy(final String password, final int numIterations, final InternalEncryptionService encryptionService) {
    super(null, encryptionService);
    this.password = password;
    this.numIterations = numIterations;
    this.secureRandom = encryptionService.getSecureRandom();
  }

  public List<Byte> generateSalt() {
    final byte[] salt = new byte[SALT_SIZE];

    secureRandom.nextBytes(salt);
    secureRandom.nextBytes(salt);

    return unmodifiableList(asList(ArrayUtils.toObject(salt)));
  }

  public Key deriveKey() {
    if (salt == null) {
      salt = generateSalt();
    }
    return deriveKey(salt);
  }

  public Key deriveKey(final List<Byte> salt) {
    final Byte[] saltArray = salt.toArray(new Byte[0]);
    final PBEKeySpec pbeSpec = new PBEKeySpec(password.toCharArray(), toPrimitive(saltArray), numIterations,
      KEY_BIT_LENGTH);

    try {
      final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384");
      final SecretKey pbeKey = keyFactory.generateSecret(pbeSpec);
      return new SecretKeySpec(pbeKey.getEncoded(), "AES");
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(final String password) {
    this.password = password;
  }

  @Override
  public List<Byte> getSalt() {
    return salt;
  }

  @Override
  public boolean matchesCanary(final EncryptionKeyCanary canary) {
    if (canary.getSalt() == null || canary.getSalt().length == 0) {
      return false;
    }

    final Key key = deriveKey(unmodifiableList(asList(ArrayUtils.toObject(canary.getSalt()))));

    final boolean result = super.matchesCanary(key, canary);
    if (result) {
      setKey(key);
    }
    return result;
  }

  @Override
  public Key getKey() {
    if (super.getKey() == null) {
      setKey(deriveKey());
    }

    return super.getKey();
  }
}
