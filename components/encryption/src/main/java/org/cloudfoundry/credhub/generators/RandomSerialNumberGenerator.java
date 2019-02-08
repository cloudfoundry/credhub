package org.cloudfoundry.credhub.generators;

import java.math.BigInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.services.RandomNumberGenerator;

@Component
public class RandomSerialNumberGenerator {

  /* The maximum length for serial number for X509 Certificates
   *  is limited to 20 bytes = 159 bits.
   *  http://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers
   *  */
  private static final int NUM_BITS_IN_CERT_SERIAL_NUM = 159;
  private final RandomNumberGenerator randomNumberGenerator;

  @Autowired
  public RandomSerialNumberGenerator(final RandomNumberGenerator randomNumberGenerator) {
    super();
    this.randomNumberGenerator = randomNumberGenerator;
  }

  public BigInteger generate() {
    return new BigInteger(NUM_BITS_IN_CERT_SERIAL_NUM, randomNumberGenerator.getSecureRandom());
  }
}
