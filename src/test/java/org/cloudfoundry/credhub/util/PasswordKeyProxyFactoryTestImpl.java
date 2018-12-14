package org.cloudfoundry.credhub.util;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.service.InternalEncryptionService;
import org.cloudfoundry.credhub.service.KeyProxy;
import org.cloudfoundry.credhub.service.PasswordBasedKeyProxy;
import org.cloudfoundry.credhub.service.PasswordKeyProxyFactory;

@Component
@Profile("unit-test")
public class PasswordKeyProxyFactoryTestImpl implements PasswordKeyProxyFactory {
  @Override
  public KeyProxy createPasswordKeyProxy(
    final EncryptionKeyMetadata encryptionKeyMetadata, final InternalEncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), 1, encryptionService);
  }
}
