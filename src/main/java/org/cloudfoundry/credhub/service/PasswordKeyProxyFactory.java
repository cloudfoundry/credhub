package org.cloudfoundry.credhub.service;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;

@Component
@Profile("!unit-test")
public interface PasswordKeyProxyFactory {
  KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, InternalEncryptionService encryptionService);
}
