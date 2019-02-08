package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.util.List;

import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;

public interface KeyProxy {

  Key getKey();

  boolean matchesCanary(EncryptionKeyCanary canary);

  List<Byte> getSalt();
}
