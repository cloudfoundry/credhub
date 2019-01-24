package org.cloudfoundry.credhub.generator;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class RsaKeyPairGeneratorTest {
  private RsaKeyPairGenerator subject;

  @Before
  public void beforeEach() throws Exception {

    subject = new RsaKeyPairGenerator();
  }

  @Test
  public void generateKeyPair_generatesKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
    final KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }
}
