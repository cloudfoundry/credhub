package org.cloudfoundry.credhub.helper;

import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;

final public class EncryptionCanaryHelper {

  private EncryptionCanaryHelper() {
  }

  public static EncryptionKeyCanary addCanary(
    EncryptionKeyCanaryDataService encryptionKeyCanaryDataService) {
    EncryptionKeyCanary testCanary = new EncryptionKeyCanary();
    testCanary.setEncryptedCanaryValue("expectedCanaryValue".getBytes());
    testCanary.setNonce("nonce".getBytes());

    encryptionKeyCanaryDataService.save(testCanary);

    return testCanary;
  }
}
