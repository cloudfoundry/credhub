package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

@Component
@ConditionalOnProperty(value = "hsm.disabled", havingValue = "false", matchIfMissing = true)
public class LunaEncryptionConfiguration implements EncryptionConfiguration {

  private static final String ENCRYPTION_KEY_ALIAS = "io.pivotal.security.credhub";

  @Value("hsm.partition-password")
  String partitionPassword;

  private Provider provider;
  private SecureRandom secureRandom;
  private KeyGenerator aesKeyGenerator;
  private KeyStore keyStore;
  private Key key;

  public LunaEncryptionConfiguration() throws Exception {
    provider = (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance();
    Security.addProvider(provider);

    Object lunaSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager").getDeclaredMethod("getInstance").invoke(null);
    lunaSlotManager.getClass().getMethod("login", String.class).invoke(lunaSlotManager, partitionPassword);

    keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("LunaRNG");
    aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);

    if (!keyStore.containsAlias(ENCRYPTION_KEY_ALIAS)) {
      SecretKey aesKey = aesKeyGenerator.generateKey();
      keyStore.setKeyEntry(ENCRYPTION_KEY_ALIAS, aesKey, null, null);
    }
    key = keyStore.getKey(ENCRYPTION_KEY_ALIAS, null);
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  @Override
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  public Key getKey() {
    return key;
  }
}
