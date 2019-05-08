package org.cloudfoundry.credhub;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.services.InternalEncryptionService;
import org.cloudfoundry.credhub.services.KeyProxy;
import org.cloudfoundry.credhub.services.PasswordBasedKeyProxy;
import org.cloudfoundry.credhub.services.PasswordKeyProxyFactory;

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
