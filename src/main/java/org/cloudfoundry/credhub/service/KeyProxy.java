package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;

import java.security.Key;
import java.util.List;

public interface KeyProxy {

  Key getKey();

  boolean matchesCanary(EncryptionKeyCanary canary);

  List<Byte> getSalt();
}
