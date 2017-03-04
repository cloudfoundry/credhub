package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionService extends EncryptionService {
  private static final int KEYSIZE_BYTES = 16;
  private SecureRandom secureRandom;

  public BCEncryptionService() throws Exception {
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), new BouncyCastleProvider()));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    if (encryptionKeyMetadata.getDevKey() != null) {
      return new DefaultKeyProxy(new SecretKeySpec(DatatypeConverter.parseHexBinary(encryptionKeyMetadata.getDevKey()), 0, KEYSIZE_BYTES, "AES"), this);
    } else {
      return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), this);
    }
  }
}

