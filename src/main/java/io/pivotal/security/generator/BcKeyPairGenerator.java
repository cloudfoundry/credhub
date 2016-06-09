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
      myGenerator.initialize(3072);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    }
  }

//  protected BcKeyPairGenerator(String algorithm) {
//    super(algorithm);
//  }

  @Override
  public KeyPair generateKeyPair() {
    return myGenerator.generateKeyPair();
  }
}
