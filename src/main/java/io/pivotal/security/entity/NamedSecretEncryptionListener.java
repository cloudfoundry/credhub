package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.EncryptionServiceImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class NamedSecretEncryptionListener {

  private EncryptionService getEncryptionService() {
    return EncryptionServiceProvider.getInstance();
  }

  @PreUpdate
  @PrePersist
  public void encrypt(NamedStringSecret secret) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    if (!getEncryptionService().validate(secret.getNonce(), secret.getEncryptedValue(), secret.getValue())) {
      EncryptionServiceImpl.Encryption encryption = getEncryptionService().encrypt(secret.getValue());
      secret.setNonce(encryption.nonce);
      secret.setEncryptedValue(encryption.encryptedValue);
    }
  }

  @PostLoad
  public void decrypt(NamedStringSecret secret) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    secret.setValue(getEncryptionService().decrypt(secret.getNonce(), secret.getEncryptedValue()));
  }
}
