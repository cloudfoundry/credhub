package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class RsaKeyPairGeneratorTest {
  private RsaKeyPairGenerator subject;
  boolean initializeCalled;

  @Test
  public void generateKeyPair_integratesWithBouncyCastle() throws NoSuchProviderException, NoSuchAlgorithmException {
    BouncyCastleFipsConfigurer.configure();
    subject = new RsaKeyPairGenerator();
    final KeyPair keyPair = subject.generateKeyPair(2048);

    assertThat(keyPair.getPublic(), notNullValue());
    assertThat(keyPair.getPrivate(), notNullValue());
  }

  @Test
  public void generatesAKeyPair() {
    KeyPairGenerator generator = mock(KeyPairGenerator.class);
    final KeyPair keyPair = mock(KeyPair.class);
    when(generator.generateKeyPair()).thenReturn(keyPair);

    KeyPair result =
            RsaKeyPairGenerator.constructRsiKeyPairGeneratorForTesting(generator).generateKeyPair(2048);

    verify(generator).initialize(2048);
    assertSame(keyPair, result);
  }
}