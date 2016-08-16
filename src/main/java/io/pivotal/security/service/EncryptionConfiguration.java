package io.pivotal.security.service;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public interface EncryptionConfiguration {
  Provider getProvider();

  SecureRandom getSecureRandom();

  Key getKey();
}
