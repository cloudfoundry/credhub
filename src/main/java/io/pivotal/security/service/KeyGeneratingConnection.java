package io.pivotal.security.service;

import javax.crypto.KeyGenerator;
import java.security.KeyStore;

public interface KeyGeneratingConnection {
  KeyStore getKeyStore();

  KeyGenerator getKeyGenerator();
}
