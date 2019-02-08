package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.cloudfoundry.credhub.utils.StringUtil;

import static java.util.Collections.unmodifiableList;

public class ExternalKeyProxy implements KeyProxy {

  private final List<Byte> salt;
  private final EncryptionProvider encryptionProvider;
  private final EncryptionKeyMetadata encryptionKeyMetadata;

  ExternalKeyProxy(final EncryptionKeyMetadata encryptionKeyMetadata, final EncryptionProvider encryptionProvider) {
    super();
    this.encryptionKeyMetadata = encryptionKeyMetadata;
    this.encryptionProvider = encryptionProvider;
    this.salt = unmodifiableList(new ArrayList<>());
  }

  @Override
  public Key getKey() {
    return null;
  }

  @Override
  public boolean matchesCanary(final EncryptionKeyCanary canary) {
    return matchesCanary(encryptionKeyMetadata, canary);
  }

  protected boolean matchesCanary(final EncryptionKeyMetadata encryptionKeyMetadata, final EncryptionKeyCanary canary) {
    final String plaintext;

    try {
      plaintext = encryptionProvider.decrypt(new EncryptionKey(encryptionProvider, null, null, encryptionKeyMetadata.getEncryptionKeyName()), canary.getEncryptedCanaryValue(), canary.getNonce());
      return Arrays.equals(
        EncryptionKeyCanaryMapper.CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(StringUtil.UTF_8))
        || Arrays.equals(EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(
        StringUtil.UTF_8));
    } catch (final AEADBadTagException e) {
    } catch (final IllegalBlockSizeException e) {
      if (!e.getMessage().contains("returns 0x40")) {
        throw new IncorrectKeyException(e);
      }
    } catch (final Exception e) {
      throw new IncorrectKeyException(e);
    }

    return false;
  }

  @Override
  public List<Byte> getSalt() {
    return salt;
  }
}
