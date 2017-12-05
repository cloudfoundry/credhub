package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.service.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;

@Component
public class RandomSerialNumberGenerator {

  /* The maximum length for serial number for X509 Certificates
  *  is limited to 20 bytes = 159 bits.
  *  http://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers
  *  */
  private static final int NUM_BITS_IN_CERT_SERIAL_NUM = 159;
  private final EncryptionService encryptionService;

  @Autowired
  public RandomSerialNumberGenerator(EncryptionService encryptionService) {
    this.encryptionService = encryptionService;
  }

  public BigInteger generate() {
    return new BigInteger(NUM_BITS_IN_CERT_SERIAL_NUM, encryptionService.getSecureRandom());
  }
}
