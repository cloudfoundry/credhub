package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class RsaKeyPairGeneratorTest {
  private RsaKeyPairGenerator subject;

  @BeforeEach
  public void beforeEach() throws Exception {
    BouncyCastleFipsConfigurer.configure();
    subject = new RsaKeyPairGenerator();
  }

  @Test
  public void generateKeyPair_generatesKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
    final KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }
}
