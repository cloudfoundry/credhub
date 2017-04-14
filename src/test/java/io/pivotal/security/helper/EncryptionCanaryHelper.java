package io.pivotal.security.helper;

import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;

public class EncryptionCanaryHelper {

  public static EncryptionKeyCanary addCanary(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService) {
    EncryptionKeyCanary testCanary = new EncryptionKeyCanary();
    testCanary.setEncryptedCanaryValue("expectedCanaryValue".getBytes());
    testCanary.setNonce("nonce".getBytes());

    encryptionKeyCanaryDataService.save(testCanary);

    return testCanary;
  }
}
