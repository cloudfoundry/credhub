package org.cloudfoundry.credhub.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.data.EncryptedValueDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class EncryptionKeyRotator {

  private final EncryptedValueDataService encryptedValueDataService;
  private EncryptionKeySet keySet;
  private final Logger logger;
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyRotator(
      EncryptedValueDataService encryptedValueDataService,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      EncryptionKeySet keySet
  ) {
    this.encryptedValueDataService = encryptedValueDataService;
    this.keySet = keySet;
    this.logger = LogManager.getLogger(this.getClass());
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  public void rotate() {
    final long start = System.currentTimeMillis();
    logger.info("Starting encryption key rotation.");
    int rotatedRecordCount = 0;

    final long startingNotRotatedRecordCount = encryptedValueDataService
        .countAllByCanaryUuid(keySet.getActive().getUuid());

    List<UUID> inactiveCanaries = keySet.getInactiveUuids();
    Slice<EncryptedValue> valuesEncryptedByOldKey = encryptedValueDataService
        .findByCanaryUuids(inactiveCanaries);
    while (valuesEncryptedByOldKey.hasContent()) {
      for (EncryptedValue value : valuesEncryptedByOldKey.getContent()) {
        try {
          encryptedValueDataService.rotate(value);
          rotatedRecordCount++;
        } catch (KeyNotFoundException e) {
          logger.error("key not found for value, unable to rotate");
        }
      }
      valuesEncryptedByOldKey = encryptedValueDataService.findByCanaryUuids(inactiveCanaries);
    }

    final long finish = System.currentTimeMillis();
    final long duration = finish - start;
    final long endingNotRotatedRecordCount = startingNotRotatedRecordCount - rotatedRecordCount;

    if (rotatedRecordCount == 0 && endingNotRotatedRecordCount == 0) {
      logger.info("Found no records in need of encryption key rotation.");
    } else {
      logger.info("Finished encryption key rotation in " + duration + " milliseconds. Details:");
      logger.info("  Successfully rotated " + rotatedRecordCount + " item(s)");
      logger.info("  Skipped " + endingNotRotatedRecordCount
          + " item(s) due to missing master encryption key(s).");
    }

    encryptionKeyCanaryMapper.delete(inactiveCanaries);
  }

}
