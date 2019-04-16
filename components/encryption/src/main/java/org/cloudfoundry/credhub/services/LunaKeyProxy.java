package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.AEADBadTagException;

import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.utils.StringUtil;

import static java.util.Collections.unmodifiableList;

public class LunaKeyProxy implements KeyProxy {

  private final List<Byte> salt;
  private final InternalEncryptionService encryptionService;
  private Key key;

  public LunaKeyProxy(final Key key, final InternalEncryptionService encryptionService) {
    super();
    this.key = key;
    this.encryptionService = encryptionService;
    this.salt = unmodifiableList(new ArrayList<Byte>());
  }

  @Override
  public Key getKey() {
    return key;
  }

  public void setKey(final Key key) {
    this.key = key;
  }

  @Override
  public boolean matchesCanary(final EncryptionKeyCanary canary) {
    return matchesCanary(key, canary);
  }

  protected boolean matchesCanary(final Key key, final EncryptionKeyCanary canary) {
    final String plaintext;

    try {
      plaintext = encryptionService.decrypt(key, canary.getEncryptedCanaryValue(), canary.getNonce());
      return Arrays.equals(
        EncryptionKeyCanaryMapper.CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(StringUtil.UTF_8))
        || Arrays.equals(EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE.getBytes(StringUtil.UTF_8), plaintext.getBytes(
        StringUtil.UTF_8));
    } catch (final AEADBadTagException e) {
      // internal key was wrong (do noting, fall through to `return false`
    } catch (final Exception e) {
      if (errorIsSomethingOtherThanTheKeyBeingIncorrect(e)) {
        throw new RuntimeException(e);
      }
      // internal key was wrong (do noting, fall through to `return false`
    }

    return false;
  }

  private boolean errorIsSomethingOtherThanTheKeyBeingIncorrect(final Exception e) {
    return e.getCause() == null || !e.getCause().getMessage().contains("returns 0x40 (CKR_ENCRYPTED_DATA_INVALID)");
  }

  @Override
  public List<Byte> getSalt() {
    return salt;
  }
}
