package io.pivotal.security.service;

import io.pivotal.security.entity.EncryptionKeyCanary;

import java.security.Key;
import java.util.List;

public interface KeyProxy {
  Key getKey();

  boolean matchesCanary(EncryptionKeyCanary canary);

  List<Byte> getSalt();
}
