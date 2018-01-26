package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.config.LunaProviderProperties;
import org.cloudfoundry.credhub.config.ProviderType;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
public class EncryptionProviderFactory {

  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private LunaProviderProperties lunaProviderProperties;
  private TimedRetry timedRetry;
  private PasswordKeyProxyFactory passwordKeyProxyFactory;
  private HashMap<ProviderType, EncryptionService> map;

  @Autowired
  public EncryptionProviderFactory(EncryptionKeysConfiguration keysConfiguration,
      LunaProviderProperties lunaProviderProperties, TimedRetry timedRetry,
      PasswordKeyProxyFactory passwordKeyProxyFactory) throws Exception {
    this.encryptionKeysConfiguration = keysConfiguration;
    this.lunaProviderProperties = lunaProviderProperties;
    this.timedRetry = timedRetry;
    this.passwordKeyProxyFactory = passwordKeyProxyFactory;
    map = new HashMap<>();
  }

  public EncryptionService getEncryptionService(ProviderType provider) throws Exception {
    EncryptionService encryptionService;

    if (map.containsKey(provider)) {
      return map.get(provider);
    } else {
      switch (provider) {
        case HSM:
          encryptionService = new LunaEncryptionService(new LunaConnection(lunaProviderProperties),
              encryptionKeysConfiguration.isKeyCreationEnabled(),
              timedRetry);
          break;
        default:
          encryptionService = new InternalEncryptionService(passwordKeyProxyFactory);
      }
      map.put(provider, encryptionService);
      return encryptionService;
    }
  }
}
