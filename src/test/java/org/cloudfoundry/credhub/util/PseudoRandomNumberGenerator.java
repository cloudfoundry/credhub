package org.cloudfoundry.credhub.util;

import java.security.SecureRandom;

import org.cloudfoundry.credhub.service.RandomNumberGenerator;

public class PseudoRandomNumberGenerator implements RandomNumberGenerator {

  @Override
  public SecureRandom getSecureRandom() {
    return new SecureRandom();
  }
}
