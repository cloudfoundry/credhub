package org.cloudfoundry.credhub.services;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Component;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.data.EncryptedValueDataService;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;

@Component
public class EncryptionKeyRotator {

  private final EncryptedValueDataService encryptedValueDataService;
  private static final Logger LOGGER = LogManager.getLogger(EncryptionKeyRotator.class);
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final EncryptionKeySet keySet;

  @Autowired
  EncryptionKeyRotator(
    final EncryptedValueDataService encryptedValueDataService,
    final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
    final EncryptionKeySet keySet
  ) {
    super();
    this.encryptedValueDataService = encryptedValueDataService;
    this.keySet = keySet;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  public void rotate() {
    final long start = System.currentTimeMillis();
    LOGGER.info("Starting encryption key rotation.");
    int rotatedRecordCount = 0;

    final long startingNotRotatedRecordCount = encryptedValueDataService
      .countAllByCanaryUuid(keySet.getActive().getUuid());

    final List<UUID> inactiveCanaries = keySet.getInactiveUuids();
    Slice<EncryptedValue> valuesEncryptedByOldKey = encryptedValueDataService
      .findByCanaryUuids(inactiveCanaries);
    while (valuesEncryptedByOldKey.hasContent()) {
      for (final EncryptedValue value : valuesEncryptedByOldKey.getContent()) {
        try {
          encryptedValueDataService.rotate(value);
          rotatedRecordCount++;
        } catch (final KeyNotFoundException e) {
          LOGGER.error("key not found for value, unable to rotate");
        }
      }
      valuesEncryptedByOldKey = encryptedValueDataService.findByCanaryUuids(inactiveCanaries);
    }

    final long finish = System.currentTimeMillis();
    final long duration = finish - start;
    final long endingNotRotatedRecordCount = startingNotRotatedRecordCount - rotatedRecordCount;

    if (rotatedRecordCount == 0 && endingNotRotatedRecordCount == 0) {
      LOGGER.info("Found no records in need of encryption key rotation.");
    } else {
      LOGGER.info("Finished encryption key rotation in " + duration + " milliseconds. Details:");
      LOGGER.info("  Successfully rotated " + rotatedRecordCount + " item(s)");
      LOGGER.info("  Skipped " + endingNotRotatedRecordCount
        + " item(s) due to missing master encryption key(s).");
    }

    encryptionKeyCanaryMapper.delete(inactiveCanaries);
  }

}
