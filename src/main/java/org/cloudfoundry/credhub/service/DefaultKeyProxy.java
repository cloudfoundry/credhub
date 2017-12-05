package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.cloudfoundry.credhub.util.StringUtil;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

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
      return Arrays.equals(
          EncryptionKeyCanaryMapper.CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(StringUtil.UTF_8))
          || Arrays.equals(EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(
          StringUtil.UTF_8));
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
