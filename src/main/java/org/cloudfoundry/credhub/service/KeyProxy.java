package org.cloudfoundry.credhub.service;

import java.security.Key;
import java.util.List;

import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;

public interface KeyProxy {

  Key getKey();

  boolean matchesCanary(EncryptionKeyCanary canary);

  List<Byte> getSalt();
}
