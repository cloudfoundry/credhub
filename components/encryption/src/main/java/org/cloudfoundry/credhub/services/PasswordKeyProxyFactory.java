package org.cloudfoundry.credhub.services;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;

public interface PasswordKeyProxyFactory {
  KeyProxy createPasswordKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata, InternalEncryptionService encryptionService);
}
