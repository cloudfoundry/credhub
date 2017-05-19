package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.exceptions.IncorrectKeyException;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE;
import static java.util.Collections.unmodifiableList;

class DefaultKeyProxy implements KeyProxy {

  private final List<Byte> salt;
  private final EncryptionService encryptionService;
  private Key key;

  DefaultKeyProxy(Key key, EncryptionService encryptionService) {
    this.key = key;
    this.encryptionService = encryptionService;
    this.salt = unmodifiableList(new ArrayList<Byte>());
  }

  @Override
  public Key getKey() {
    return key;
  }

  public void setKey(Key key) {
    this.key = key;
  }

  public boolean matchesCanary(EncryptionKeyCanary canary) {
    return matchesCanary(key, canary);
  }

  protected boolean matchesCanary(Key key, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = encryptionService.decrypt(key, canary.getEncryptedCanaryValue(), canary.getNonce());
      return Arrays.equals(CANARY_VALUE.getBytes(), plaintext.getBytes())
          || Arrays.equals(DEPRECATED_CANARY_VALUE.getBytes(), plaintext.getBytes());
    } catch (AEADBadTagException e) {
      // internal key was wrong
    } catch (IllegalBlockSizeException e) {
      // Our guess(es) at "HSM key was wrong":
      if (!e.getMessage().contains("returns 0x40")) {
        throw new IncorrectKeyException(e);
      }
      // Could not process input data: function 'C_Decrypt' returns 0x40
    } catch (Exception e) {
      throw new IncorrectKeyException(e);
    }

    return false;
  }

  @Override
  public List<Byte> getSalt() {
    return salt;
  }
}
