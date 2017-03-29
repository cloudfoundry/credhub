package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionService extends EncryptionServiceWithConnection {

  private final LunaConnection lunaConnection;

  @Autowired
  public LunaEncryptionService(LunaConnection lunaConnection) {
    this.lunaConnection = lunaConnection;

    lunaConnection.reconnect(null);
  }

  @Override
  SecureRandom getSecureRandom() {
    return lunaConnection.getSecureRandom();
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(
        Cipher.getInstance(CipherTypes.GCM.toString(), lunaConnection.getProvider()));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new DefaultKeyProxy(createKey(encryptionKeyMetadata, lunaConnection), this);
  }
}
