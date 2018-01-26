package org.cloudfoundry.credhub.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.lang3.ArrayUtils.toPrimitive;

@Component
public class EncryptionKeyCanaryMapper {

  public static final Charset CHARSET = Charset.defaultCharset();
  public static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  public static final String DEPRECATED_CANARY_VALUE = new String(new byte[64], CHARSET);
  public static final int CANARY_POPULATION_WAIT_SEC = 60 * 10; // ten minutes

  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private final TimedRetry timedRetry;
  private EncryptionProviderFactory providerFactory;
  private final Logger logger;

  @Autowired
  EncryptionKeyCanaryMapper(
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      TimedRetry timedRetry,
      EncryptionProviderFactory providerFactory
  ) {
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;
    this.timedRetry = timedRetry;
    this.providerFactory = providerFactory;

    logger = LogManager.getLogger();
  }

  void mapUuidsToKeys(EncryptionKeySet keySet) throws Exception {
    List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();

    for (EncryptionKeyMetadata keyMetadata : encryptionKeysConfiguration.getKeys()) {
      EncryptionService encryptionService = providerFactory.getEncryptionService(keyMetadata.getProviderType());
      KeyProxy keyProxy = encryptionService.createKeyProxy(keyMetadata);
      EncryptionKeyCanary matchingCanary = null;

      for (EncryptionKeyCanary canary : encryptionKeyCanaries) {
        if (keyProxy.matchesCanary(canary)) {
          matchingCanary = canary;
          break;
        }
      }

      if (matchingCanary == null) {
        if (keyMetadata.isActive()) {
          matchingCanary = createCanary(keyProxy, encryptionService);
        } else {
          continue;
        }
      }
      if (keyMetadata.isActive()) {
        keySet.setActive(matchingCanary.getUuid());
      }
      try {
        keySet.add(new EncryptionKey(
            providerFactory.getEncryptionService(keyMetadata.getProviderType()),
            matchingCanary.getUuid(),
            keyProxy.getKey()));
      } catch (Exception e) {
        throw new RuntimeException("Failed to connect to encryption provider", e);
      }
    }

    if (keySet.getActive() == null) {
      throw new RuntimeException("No active key was found");
    }
  }

  private EncryptionKeyCanary createCanary(KeyProxy keyProxy, EncryptionService encryptionService) {
    if (encryptionKeysConfiguration.isKeyCreationEnabled()) {
      logger.info("Creating a new active key canary");
      EncryptionKeyCanary canary = new EncryptionKeyCanary();

      try {
        EncryptedValue encryptionData = encryptionService
            .encrypt(null, keyProxy.getKey(), CANARY_VALUE);
        canary.setEncryptedCanaryValue(encryptionData.getEncryptedValue());
        canary.setNonce(encryptionData.getNonce());
        final List<Byte> salt = keyProxy.getSalt();
        final Byte[] saltArray = new Byte[salt.size()];
        canary.setSalt(toPrimitive(salt.toArray(saltArray)));

      } catch (Exception e) {
        throw new RuntimeException(e);
      }

      return encryptionKeyCanaryDataService.save(canary);
    } else {
      final EncryptionKeyCanary[] matchingCanary = new EncryptionKeyCanary[1];
      timedRetry.retryEverySecondUntil(CANARY_POPULATION_WAIT_SEC, () -> {
        for (EncryptionKeyCanary encryptionKeyCanary : encryptionKeyCanaryDataService.findAll()) {
          if (keyProxy.matchesCanary(encryptionKeyCanary)) {
            matchingCanary[0] = encryptionKeyCanary;
            return true;
          }
        }
        logger.info("Waiting for the active key's canary");
        return false;
      });
      if (matchingCanary[0] == null) {
        throw new RuntimeException("Timed out waiting for active key canary to be created");
      }
      return matchingCanary[0];
    }
  }

  public void delete(List<UUID> uuids) {
    encryptionKeyCanaryDataService.delete(uuids);
  }

}
