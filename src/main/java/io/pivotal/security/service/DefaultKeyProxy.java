package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;

class DefaultKeyProxy implements KeyProxy {
  private Key key;
  private EncryptionService encryptionService;

  DefaultKeyProxy(Key key, EncryptionService encryptionService) {
    this.key = key;
    this.encryptionService = encryptionService;
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

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  protected boolean matchesCanary(Key key, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = encryptionService.decrypt(key, canary.getEncryptedValue(), canary.getNonce());
      return EncryptionKeyCanaryMapper.CANARY_VALUE.equals(plaintext);
    } catch (AEADBadTagException e) {
      // internal key was wrong
    } catch (IllegalBlockSizeException e) {
      // Our guess(es) at "HSM key was wrong":
      if (!e.getMessage().contains("returns 0x40")) {
        throw new RuntimeException(e);
      }
      // Could not process input data: function 'C_Decrypt' returns 0x40
    } catch (BadPaddingException e) {
      // Our guess(es) at "DSM key was wrong":
      if (!e.getMessage().contains("rv=48")) {
        throw new RuntimeException(e);
      }
      // javax.crypto.BadPaddingException: Decrypt error: rv=48
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return false;
  }
}
