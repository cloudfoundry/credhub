package io.pivotal.security.service;

import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

import static java.util.Arrays.asList;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionService extends EncryptionService {

  @Value("${hsm.partition}")
  String partitionName;

  @Value("${hsm.partition-password}")
  String partitionPassword;

  @Value("${hsm.encryption-key-name}")
  String encryptionKeyAlias;

  private final Provider provider;
  private SecureRandom secureRandom;
  private Key key;
  private List<Key> keys;
  private LunaSlotManagerProxy lunaSlotManager;

  public LunaEncryptionService() throws Exception {
    this(
        (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance(),
        LunaSlotManagerProxy.getInstance()
    );
  }

  public LunaEncryptionService(Provider provider, LunaSlotManagerProxy lunaSlotManager) {
    this.provider = provider;
    this.lunaSlotManager = lunaSlotManager;
    Security.addProvider(provider);
  }

  @PostConstruct
  private void initialize() throws Exception {
    initializeKeys();
    keys = asList(key);
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
  public Key getActiveKey() {
    return key;
  }

  @Override
  public List<Key> getKeys() {
    return keys;
  }

  @Override
  public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), provider));
  }

  @Override
  public Encryption encrypt(Key key, String value) throws Exception {
    try {
      return super.encrypt(key, value);
    } catch(IllegalBlockSizeException e) {
      reconnect();
      return super.encrypt(key, value);
    }
  }

  @Override
  public String decrypt(Key key, byte[] encryptedValue, byte[] nonce) throws Exception {
    try {
      return super.decrypt(key, encryptedValue, nonce);
    } catch(IllegalBlockSizeException e) {
      reconnect();
      return super.decrypt(key, encryptedValue, nonce);
    }
  }

  @Override
  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  protected void initializeKeys() throws Exception {
    login();

    KeyStore keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("LunaRNG");
    KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);

    if (!keyStore.containsAlias(encryptionKeyAlias)) {
      SecretKey aesKey = aesKeyGenerator.generateKey();
      keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null, null);
    }

    key = keyStore.getKey(encryptionKeyAlias, null);
  }

  protected void login() throws Exception {
    lunaSlotManager.login(partitionName, partitionPassword);
  }

  private void reconnect() throws Exception {
    lunaSlotManager.reinitialize();
    login();
  }

  protected static class LunaSlotManagerProxy {
    private static LunaSlotManagerProxy instance;
    private Object proxiedSlotManager;
    private final Method loginMethod;
    private final Method reinitializeMethod;

    public static LunaSlotManagerProxy getInstance() throws Exception {
      if (instance == null) {
        final Object proxiedSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager").getDeclaredMethod("getInstance").invoke(null);
        instance = new LunaSlotManagerProxy(proxiedSlotManager);
      }
      return instance;
    }

    public LunaSlotManagerProxy(Object proxiedSlotManager) throws Exception {
      this.proxiedSlotManager = proxiedSlotManager;
      loginMethod = proxiedSlotManager.getClass().getMethod("login", String.class, String.class);
      reinitializeMethod = proxiedSlotManager.getClass().getMethod("reinitialize");
    }

    public void login(String partitionName, String partitionPassword) throws Exception {
      loginMethod.invoke(proxiedSlotManager, partitionName, partitionPassword);
    }

    public void reinitialize() throws Exception {
      reinitializeMethod.invoke(proxiedSlotManager);
    }
  }
}
