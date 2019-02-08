package org.cloudfoundry.credhub.helpers;

import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.utils.StringUtil;

final public class EncryptionCanaryHelper {

  private EncryptionCanaryHelper() {
    super();
  }

  public static EncryptionKeyCanary addCanary(
    final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService) {
    final EncryptionKeyCanary testCanary = new EncryptionKeyCanary();
    testCanary.setEncryptedCanaryValue("expectedCanaryValue".getBytes(StringUtil.UTF_8));
    testCanary.setNonce("nonce".getBytes(StringUtil.UTF_8));

    encryptionKeyCanaryDataService.save(testCanary);

    return testCanary;
  }
}
