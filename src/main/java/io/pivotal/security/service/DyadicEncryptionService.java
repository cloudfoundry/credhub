package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

@SuppressWarnings("unused")
@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dsm")
public class DyadicEncryptionService extends EncryptionServiceWithConnection {
  private final DyadicConnection dyadicConnection;

  private SecureRandom secureRandom;

  @Autowired
  DyadicEncryptionService(DyadicConnection dyadicConnection) throws Exception {
    this.dyadicConnection = dyadicConnection;
    this.secureRandom = new SecureRandom();
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  EncryptionService.CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    final String ccmCipherName = CipherTypes.CCM.toString();
    final Provider dyadicConnectionProvider = dyadicConnection.getProvider();

    return new CipherWrapper(Cipher.getInstance(ccmCipherName, dyadicConnectionProvider));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return dyadicConnection.generateParameterSpec(nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new KeyProxy(createKey(encryptionKeyMetadata, dyadicConnection));
  }
}
