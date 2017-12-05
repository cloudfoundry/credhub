package org.cloudfoundry.credhub.util;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.service.EncryptionService;
import org.cloudfoundry.credhub.service.KeyProxy;
import org.cloudfoundry.credhub.service.PasswordBasedKeyProxy;
import org.cloudfoundry.credhub.service.PasswordKeyProxyFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("unit-test")
public class PasswordKeyProxyFactoryTestImpl implements PasswordKeyProxyFactory {
  public KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), 1, encryptionService);
  }
}
