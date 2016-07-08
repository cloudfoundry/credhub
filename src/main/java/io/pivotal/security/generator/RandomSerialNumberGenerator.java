package io.pivotal.security.generator;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class RandomSerialNumberGenerator {

  /* The maximum length for serial number for X509 Certificates
  *  is limited to 20 bytes = 159 bits.
  *  http://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers
  *  */
  private static final int NUM_BITS_IN_CERT_SERIAL_NUM = 159;

  public BigInteger generate() throws NoSuchAlgorithmException {
    return new BigInteger(NUM_BITS_IN_CERT_SERIAL_NUM, SecureRandom.getInstanceStrong());
  }
}
