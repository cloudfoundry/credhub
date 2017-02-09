package io.pivotal.security.service;

import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Component;

@Component
public class EncryptionKeyRotator {
  private final SecretEncryptionHelper secretEncryptionHelper;
  private final SecretDataService secretDataService;
  private final Logger logger;

  EncryptionKeyRotator(
      SecretEncryptionHelper secretEncryptionHelper,
      SecretDataService secretDataService
  ) {
    this.secretEncryptionHelper = secretEncryptionHelper;
    this.secretDataService = secretDataService;
    this.logger = LogManager.getLogger(this.getClass());
  }

  public void rotate() {
    final long start = System.currentTimeMillis();
    logger.info("Starting encryption key rotation.");
    int rotatedRecordCount = 0;

    final long startingNotRotatedRecordCount = secretDataService.countAllNotEncryptedByActiveKey();

    Slice<NamedSecret> secretsEncryptedByOldKey = secretDataService.findEncryptedWithAvailableInactiveKey();
    while (secretsEncryptedByOldKey.hasContent()) {
      for (NamedSecret secret : secretsEncryptedByOldKey.getContent()) {
        secretEncryptionHelper.rotate(secret);
        secretDataService.save(secret);
        rotatedRecordCount++;
      }
      secretsEncryptedByOldKey = secretDataService.findEncryptedWithAvailableInactiveKey();
    }

    final long finish = System.currentTimeMillis();
    final long duration = finish - start;
    final long endingNotRotatedRecordCount = startingNotRotatedRecordCount - rotatedRecordCount;

    if (rotatedRecordCount == 0 && endingNotRotatedRecordCount == 0) {
      logger.info("Found no records in need of encryption key rotation.");
    } else {
      logger.info("Finished encryption key rotation in " + duration + " milliseconds. Details:");
      logger.info("  Successfully rotated " + rotatedRecordCount + " item(s)");
      logger.info("  Skipped " + endingNotRotatedRecordCount + " item(s) due to missing master encryption key(s).");
    }
  }
}
