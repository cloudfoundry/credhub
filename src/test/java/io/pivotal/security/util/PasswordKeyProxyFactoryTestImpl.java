package io.pivotal.security.util;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.KeyProxy;
import io.pivotal.security.service.PasswordBasedKeyProxy;
import io.pivotal.security.service.PasswordKeyProxyFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("unit-test")
public class PasswordKeyProxyFactoryTestImpl implements PasswordKeyProxyFactory {
  public KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), 1, encryptionService);
  }
}
