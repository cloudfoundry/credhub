package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import static io.pivotal.security.constants.EncryptionConstants.ITERATIONS;

@Component
@Profile("!unit-test")
public class PasswordKeyProxyFactoryImpl implements PasswordKeyProxyFactory {
  public KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), ITERATIONS, encryptionService);
  }
}
