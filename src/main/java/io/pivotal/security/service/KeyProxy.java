package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;

import java.security.Key;

public interface KeyProxy {
  Key getKey();

  boolean matchesCanary(EncryptionKeyCanary canary);

  byte[] getSalt();
}
