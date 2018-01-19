package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.config.LunaProviderProperties;
import org.cloudfoundry.credhub.config.ProviderType;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class EncryptionProviderFactory {

  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private LunaProviderProperties lunaProviderProperties;
  private TimedRetry timedRetry;
  private PasswordKeyProxyFactory passwordKeyProxyFactory;
  private boolean keyCreationEnabled;
  private EncryptionService encryptionService;


  @Autowired
  public EncryptionProviderFactory(EncryptionKeysConfiguration keysConfiguration,
      LunaProviderProperties lunaProviderProperties, TimedRetry timedRetry,
      PasswordKeyProxyFactory passwordKeyProxyFactory,
      @Value("${encryption.key_creation_enabled}") boolean keyCreationEnabled) throws Exception {
    this.encryptionKeysConfiguration = keysConfiguration;
    this.lunaProviderProperties = lunaProviderProperties;
    this.timedRetry = timedRetry;
    this.passwordKeyProxyFactory = passwordKeyProxyFactory;
    this.keyCreationEnabled = keyCreationEnabled;

    setEncryptionService(encryptionKeysConfiguration.getProvider());

  }

  private void setEncryptionService(ProviderType type) throws Exception {
    if (type.equals(ProviderType.HSM)) {
      encryptionService = new LunaEncryptionService(new LunaConnection(lunaProviderProperties), keyCreationEnabled,
          timedRetry);
    }
    else {
       encryptionService = new InternalEncryptionService(passwordKeyProxyFactory);
      }
  }

  @Bean
  public EncryptionService getEncryptionService(){
    return encryptionService;
  }

}
