package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.KeyPair;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class BcKeyPairGeneratorTest {

  @Autowired(required = true)
  private BcKeyPairGenerator subject;

  @Test
  public void canGenerateKeyPair() throws Exception {
    KeyPair keyPair = subject.generateKeyPair();

    assertThat(keyPair.getPublic().getAlgorithm(), equalTo("RSA"));
    assertThat(keyPair.getPrivate().getAlgorithm(), equalTo("RSA"));
    assertThat(keyPair.getPublic().getFormat(), equalTo("X.509"));
    assertThat(keyPair.getPrivate().getFormat(), equalTo("PKCS#8"));
  }
}