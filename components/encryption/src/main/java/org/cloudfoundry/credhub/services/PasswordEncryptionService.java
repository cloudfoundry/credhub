package org.cloudfoundry.credhub.services;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.CipherTypes;


public class PasswordEncryptionService extends InternalEncryptionService {
  public static final int GCM_TAG_LENGTH = 128;
  private final PasswordKeyProxyFactory passwordKeyProxyFactory;

  public PasswordEncryptionService(final PasswordKeyProxyFactory passwordKeyProxyFactory) throws Exception {
    super();
    this.passwordKeyProxyFactory = passwordKeyProxyFactory;
  }

  @Override
  public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString()));
  }

  @Override
  public AlgorithmParameterSpec generateParameterSpec(final byte[] nonce) {
    return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
  }

  @Override
  public KeyProxy createKeyProxy(final EncryptionKeyMetadata encryptionKeyMetadata) {
    return passwordKeyProxyFactory.createPasswordKeyProxy(encryptionKeyMetadata, this);
  }
}

