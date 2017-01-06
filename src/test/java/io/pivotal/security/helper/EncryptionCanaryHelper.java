package io.pivotal.security.helper;

import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;

public class EncryptionCanaryHelper {
  public static void addCanary(EncryptionKeyCanaryDataService encryptionKeyCanaryDataService) {
    EncryptionKeyCanary testCanary = new EncryptionKeyCanary();
    testCanary.setEncryptedValue("expectedCanaryValue".getBytes());
    testCanary.setNonce("nonce".getBytes());
    encryptionKeyCanaryDataService.save(testCanary);
  }
}
