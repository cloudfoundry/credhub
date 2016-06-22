package io.pivotal.security.generator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.security.*;

@Component
public class BcKeyPairGenerator extends KeyPairGenerator {

  private KeyPairGenerator myGenerator;

  public BcKeyPairGenerator() {
    super("RSA");
    Security.addProvider(new BouncyCastleProvider());
    try {
      myGenerator = KeyPairGenerator.getInstance("RSA", "BC");
      myGenerator.initialize(2048);
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
