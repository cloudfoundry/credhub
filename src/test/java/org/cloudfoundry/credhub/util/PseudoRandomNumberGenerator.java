package org.cloudfoundry.credhub.util;

import org.cloudfoundry.credhub.service.RandomNumberGenerator;

import java.security.SecureRandom;

public class PseudoRandomNumberGenerator implements RandomNumberGenerator {

  @Override
  public SecureRandom getSecureRandom() {
    return new SecureRandom();
  }
}
