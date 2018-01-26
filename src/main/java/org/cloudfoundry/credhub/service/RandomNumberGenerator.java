package org.cloudfoundry.credhub.service;

import java.security.SecureRandom;

public interface RandomNumberGenerator {

  SecureRandom getSecureRandom();
}
