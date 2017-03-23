package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.List;

import static io.pivotal.security.constants.EncryptionConstants.ITERATIONS;
import static io.pivotal.security.constants.EncryptionConstants.KEY_BIT_LENGTH;
import static io.pivotal.security.constants.EncryptionConstants.SALT_SIZE;
import static java.util.Arrays.asList;
import static org.apache.commons.lang3.ArrayUtils.toPrimitive;

public class PasswordBasedKeyProxy extends DefaultKeyProxy implements KeyProxy {
  private String password = null;
  private List<Byte> salt;

  public PasswordBasedKeyProxy(String password, EncryptionService encryptionService) {
    super(null, encryptionService);
    this.password = password;
  }

  public Key deriveKey(List<Byte> salt) {
    final Byte[] saltArray = salt.toArray(new Byte[salt.size()]);
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), toPrimitive(saltArray), ITERATIONS, KEY_BIT_LENGTH);

    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384");
      return skf.generateSecret(spec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public List<Byte> getSalt() {
    return salt;
  }

  @Override
  public boolean matchesCanary(EncryptionKeyCanary canary) {
    if (canary.getSalt() == null || canary.getSalt().size() == 0) {
      return false;
    }

    Key key = deriveKey(canary.getSalt());

    boolean result = super.matchesCanary(key, canary);
    if (result) {
      setKey(key);
    }
    return result;
  }

  @Override
  public Key getKey() {
    if (super.getKey() == null) {
      salt = generateSalt();
      setKey(deriveKey(salt));
    }

    return super.getKey();
  }

  public static List<Byte> generateSalt() {
    SecureRandom sr;
    byte[] salt = new byte[SALT_SIZE];
    try {
      sr = SecureRandom.getInstance("NativePRNGNonBlocking");
      sr.nextBytes(salt);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    sr.nextBytes(salt);

    return Collections.unmodifiableList(asList(ArrayUtils.toObject(salt)));
  }
}
