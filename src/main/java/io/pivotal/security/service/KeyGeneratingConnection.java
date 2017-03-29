package io.pivotal.security.service;

import java.security.KeyStore;
import javax.crypto.KeyGenerator;

public interface KeyGeneratingConnection {

  KeyStore getKeyStore();

  KeyGenerator getKeyGenerator();
}
