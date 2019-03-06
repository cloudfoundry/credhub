package org.cloudfoundry.credhub.services;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.config.EncryptionKeyProvider;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.util.TimedRetry;

@Component
public class EncryptionProviderFactory {

  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private final TimedRetry timedRetry;
  private final PasswordKeyProxyFactory passwordKeyProxyFactory;
  private final Map<String, EncryptionProvider> map;

  @Autowired
  public EncryptionProviderFactory(final EncryptionKeysConfiguration keysConfiguration, final TimedRetry timedRetry,
                                   final PasswordKeyProxyFactory passwordKeyProxyFactory) {
    super();
    this.encryptionKeysConfiguration = keysConfiguration;
    this.timedRetry = timedRetry;
    this.passwordKeyProxyFactory = passwordKeyProxyFactory;
    map = new HashMap<>();
  }

  public EncryptionProvider getEncryptionService(final EncryptionKeyProvider provider) throws Exception {
    final EncryptionProvider encryptionService;

    if (map.containsKey(provider.getProviderName())) {
      return map.get(provider.getProviderName());
    } else {
      switch (provider.getProviderType()) {
        case HSM:
          encryptionService = new LunaEncryptionService(new LunaConnection(provider.getConfiguration()),
            encryptionKeysConfiguration.isKeyCreationEnabled(),
            timedRetry);
          break;
        case KMS_PLUGIN:
          encryptionService = new KMSEncryptionProvider(provider.getConfiguration());
          break;
        default:
          encryptionService = new PasswordEncryptionService(passwordKeyProxyFactory);
          break;
      }
      map.put(provider.getProviderName(), encryptionService);
      return encryptionService;
    }
  }
}
