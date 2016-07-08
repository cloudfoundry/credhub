package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class BcKeyPairGeneratorTest {

  @Autowired(required = true)
  private BcKeyPairGenerator subject;

  @Test
  public void canGenerateKeyPair() throws Exception {
    subject.initialize(2048); // simulate default param setting of 2048
    KeyPair keyPair = subject.generateKeyPair();

    KeyFactory keyFac = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec privateKeySpec = keyFac.getKeySpec(keyPair.getPrivate(),
        RSAPrivateKeySpec.class);
    RSAPublicKeySpec publicKeySpec = keyFac.getKeySpec(keyPair.getPublic(),
        RSAPublicKeySpec.class);

    assertThat(privateKeySpec.getModulus().bitLength(), equalTo(2048));
    assertThat(publicKeySpec.getModulus().bitLength(), equalTo(2048));
    assertThat(keyPair.getPublic().getAlgorithm(), equalTo("RSA"));
    assertThat(keyPair.getPrivate().getAlgorithm(), equalTo("RSA"));
    assertThat(keyPair.getPublic().getFormat(), equalTo("X.509"));
    assertThat(keyPair.getPrivate().getFormat(), equalTo("PKCS#8"));
  }

  @Test
  public void canReinitializeLength() throws Exception {
    subject.initialize(2048);
    subject.initialize(1024); // simulate previous component initialization state being overwritten
    KeyPair keyPair = subject.generateKeyPair();

    KeyFactory keyFac = KeyFactory.getInstance("RSA");
    RSAPrivateKeySpec privateKeySpec = keyFac.getKeySpec(keyPair.getPrivate(),
        RSAPrivateKeySpec.class);
    RSAPublicKeySpec publicKeySpec = keyFac.getKeySpec(keyPair.getPublic(),
        RSAPublicKeySpec.class);

    assertThat(privateKeySpec.getModulus().bitLength(), equalTo(1024));
    assertThat(publicKeySpec.getModulus().bitLength(), equalTo(1024));
  }
}