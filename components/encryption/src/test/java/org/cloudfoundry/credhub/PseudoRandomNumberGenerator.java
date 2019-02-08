package org.cloudfoundry.credhub;

import java.security.SecureRandom;

import org.cloudfoundry.credhub.services.RandomNumberGenerator;

public class PseudoRandomNumberGenerator implements RandomNumberGenerator {

  @Override
  public SecureRandom getSecureRandom() {
    return new SecureRandom();
  }
}
