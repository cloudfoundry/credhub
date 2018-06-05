package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
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

public class ExternalKeyProxy implements  KeyProxy {

  private final List<Byte> salt;
  private final EncryptionProvider encryptionProvider;
  private EncryptionKeyMetadata encryptionKeyMetadata ;

  ExternalKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionProvider encryptionProvider) {
    this.encryptionKeyMetadata = encryptionKeyMetadata;
    this.encryptionProvider = encryptionProvider;
    this.salt = unmodifiableList(new ArrayList<Byte>());
  }

  @Override
  public Key getKey() {
    return null;
  }

  public boolean matchesCanary(EncryptionKeyCanary canary) {
    return matchesCanary(encryptionKeyMetadata, canary);
  }

  protected boolean matchesCanary(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionKeyCanary canary) {
    String plaintext;

    try {
      plaintext = encryptionProvider.decrypt(new EncryptionKey(encryptionProvider, null, null, encryptionKeyMetadata.getEncryptionKeyName()), canary.getEncryptedCanaryValue(), canary.getNonce());
      return Arrays.equals(
          EncryptionKeyCanaryMapper.CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(StringUtil.UTF_8))
          || Arrays.equals(EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(
          StringUtil.UTF_8));
    } catch (AEADBadTagException e) {
    } catch (IllegalBlockSizeException e) {
      if (!e.getMessage().contains("returns 0x40")) {
        throw new IncorrectKeyException(e);
      }
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
