package org.cloudfoundry.credhub.services;

import java.nio.charset.Charset;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeyProvider;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.TimedRetry;

import static org.apache.commons.lang3.ArrayUtils.toPrimitive;

@Component
public class EncryptionKeyCanaryMapper {

  public static final Charset CHARSET = Charset.defaultCharset();
  public static final String CANARY_VALUE = new String(new byte[128], CHARSET);
  public static final String DEPRECATED_CANARY_VALUE = new String(new byte[64], CHARSET);
  public static final int CANARY_POPULATION_WAIT_SEC = 60 * 10; // ten minutes
  private static final Logger LOGGER = LogManager.getLogger();

  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;

  private final TimedRetry timedRetry;
  private final EncryptionProviderFactory providerFactory;

  @Autowired
  public EncryptionKeyCanaryMapper(
    final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService,
    final EncryptionKeysConfiguration encryptionKeysConfiguration,
    final TimedRetry timedRetry,
    final EncryptionProviderFactory providerFactory
  ) {
    super();
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;
    this.timedRetry = timedRetry;
    this.providerFactory = providerFactory;
  }

  public void mapUuidsToKeys(final EncryptionKeySet keySet) throws Exception {
    final List<EncryptionKeyCanary> encryptionKeyCanaries = encryptionKeyCanaryDataService.findAll();
    for (final EncryptionKeyProvider provider : encryptionKeysConfiguration.getProviders()) {
      final EncryptionProvider encryptionService = providerFactory.getEncryptionService(provider);
      for (final EncryptionKeyMetadata keyMetadata : provider.getKeys()) {
        final KeyProxy keyProxy = encryptionService.createKeyProxy(keyMetadata);
        EncryptionKeyCanary matchingCanary = null;

        for (final EncryptionKeyCanary canary : encryptionKeyCanaries) {
          if (keyProxy.matchesCanary(canary)) {
            matchingCanary = canary;
            break;
          }
        }

        final EncryptionKey encryptionKey = new EncryptionKey(encryptionService, null, keyProxy.getKey(), keyMetadata.getEncryptionKeyName());

        if (matchingCanary == null) {
          if (keyMetadata.isActive()) {
            matchingCanary = createCanary(keyProxy, encryptionService, encryptionKey);
          } else {
            continue;
          }
        }
        if (keyMetadata.isActive()) {
          keySet.setActive(matchingCanary.getUuid());
        }

        try {
          encryptionKey.setUuid(matchingCanary.getUuid());
          keySet.add(encryptionKey);
        } catch (final Exception e) {
          throw new RuntimeException("Failed to connect to encryption provider", e);
        }
      }
    }
    if (keySet.getActive() == null) {
      throw new RuntimeException("No active key was found");
    }
  }

  public void delete(final List<UUID> uuids) {
    encryptionKeyCanaryDataService.delete(uuids);
  }

  private EncryptionKeyCanary createCanary(
    final KeyProxy keyProxy, final EncryptionProvider encryptionProvider, final EncryptionKey encryptionKey) {
    if (encryptionKeysConfiguration.isKeyCreationEnabled()) {
      LOGGER.info("Creating a new active key canary");
      final EncryptionKeyCanary canary = new EncryptionKeyCanary();

      try {
        final EncryptedValue encryptionData = encryptionProvider
          .encrypt(encryptionKey, CANARY_VALUE);
        canary.setEncryptedCanaryValue(encryptionData.getEncryptedValue());
        canary.setNonce(encryptionData.getNonce());
        final List<Byte> salt = keyProxy.getSalt();
        final Byte[] saltArray = new Byte[salt.size()];
        canary.setSalt(toPrimitive(salt.toArray(saltArray)));

      } catch (final Exception e) {
        throw new RuntimeException(e);
      }

      return encryptionKeyCanaryDataService.save(canary);
    } else {
      final EncryptionKeyCanary[] matchingCanary = new EncryptionKeyCanary[1];
      timedRetry.retryEverySecondUntil(CANARY_POPULATION_WAIT_SEC, () -> {
        for (final EncryptionKeyCanary encryptionKeyCanary : encryptionKeyCanaryDataService.findAll()) {
          if (keyProxy.matchesCanary(encryptionKeyCanary)) {
            matchingCanary[0] = encryptionKeyCanary;
            return true;
          }
        }
        LOGGER.info("Waiting for the active key's canary");
        return false;
      });
      if (matchingCanary[0] == null) {
        throw new RuntimeException("Timed out waiting for active key canary to be created");
      }
      return matchingCanary[0];
    }
  }
}
