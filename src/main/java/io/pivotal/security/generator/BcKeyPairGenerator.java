package io.pivotal.security.generator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

@Component
public class BcKeyPairGenerator extends KeyPairGenerator {
  static final int DEFAULT_RSA_KEY_LENGTH = 2048;

  private KeyPairGenerator myGenerator;

  public BcKeyPairGenerator() {
    super("RSA");
    Security.addProvider(new BouncyCastleProvider());
    try {
      myGenerator = KeyPairGenerator.getInstance("RSA", "BC");
      myGenerator.initialize(DEFAULT_RSA_KEY_LENGTH);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public KeyPair generateKeyPair() {
    return myGenerator.generateKeyPair();
  }

  @Override
  public void initialize(int keysize) {
    myGenerator.initialize(keysize);
  }
}
