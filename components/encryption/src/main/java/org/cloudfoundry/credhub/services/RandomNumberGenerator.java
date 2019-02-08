package org.cloudfoundry.credhub.services;

import java.security.SecureRandom;

public interface RandomNumberGenerator {

  SecureRandom getSecureRandom();
}
