package org.cloudfoundry.credhub.services;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;

@Service
@SuppressWarnings("unused")
@Profile("unit-test")
public class TestPasswordKeyProxyFactory implements PasswordKeyProxyFactory {
  @Override
  public KeyProxy createPasswordKeyProxy(
    final EncryptionKeyMetadata encryptionKeyMetadata, final InternalEncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), 1, encryptionService);
  }
}
