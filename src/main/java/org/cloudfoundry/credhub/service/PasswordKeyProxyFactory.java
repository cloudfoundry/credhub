package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!unit-test")
public interface PasswordKeyProxyFactory {
  KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, EncryptionService encryptionService);
}
