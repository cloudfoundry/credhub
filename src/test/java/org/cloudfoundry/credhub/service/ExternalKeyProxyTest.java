package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class ExternalKeyProxyTest {
  private ExternalKeyProxy subject;
  private EncryptionProvider encryptionProvider;
  private EncryptionKeyMetadata encryptionKeyMetadata;
  private EncryptionKeyCanary encryptionKeyCanary;

  @Before
  public void setUp() throws Exception {
    encryptionProvider = mock(EncryptionProvider.class);
    encryptionKeyMetadata = mock(EncryptionKeyMetadata.class);
    encryptionKeyCanary = mock(EncryptionKeyCanary.class);
  }

  @Test
  public void matchesCanary_shouldReturnTrue_IfTheCanaryDecryptsToTheCanaryValue() throws Exception {
    when(encryptionKeyCanary.getEncryptedCanaryValue()).thenReturn("value".getBytes());
    when(encryptionKeyCanary.getNonce()).thenReturn("nonce".getBytes());
    when(encryptionKeyMetadata.getEncryptionKeyName()).thenReturn("name");
    when(encryptionProvider.decrypt(any(), any(), any())).thenReturn(EncryptionKeyCanaryMapper.CANARY_VALUE);

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertTrue(subject.matchesCanary(encryptionKeyCanary));

    ArgumentCaptor<EncryptionKey> argument = ArgumentCaptor.forClass(EncryptionKey.class);
    verify(encryptionProvider).decrypt(argument.capture(), eq("value".getBytes()), eq("nonce".getBytes()));
    assertEquals(encryptionProvider, argument.getValue().getProvider());
    assertEquals("name", argument.getValue().getEncryptionKeyName());
  }

  @Test
  public void matchesCanary_shouldReturnFalse_IfTheCanaryDoesNotDecryptToTheCanaryValue() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenReturn("garbage");

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertFalse(subject.matchesCanary(encryptionKeyCanary));
  }

  @Test
  public void matchesCanary_shouldReturnTrue_IfTheCanaryDecryptsToTheDeprecatedCanaryValue() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenReturn(EncryptionKeyCanaryMapper.DEPRECATED_CANARY_VALUE);

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertTrue(subject.matchesCanary(encryptionKeyCanary));
  }

  @Test
  public void matchesCanary_shouldReturnFalse_IfTheInternalKeyWasWrong() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenThrow(AEADBadTagException.class);

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertFalse(subject.matchesCanary(encryptionKeyCanary));
  }

  @Test
  public void matchesCanary_shouldReturnFalseIfInputDataCouldNotBeProccessed_AndC_DecryptReturns_0x40() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenThrow(new IllegalBlockSizeException("returns 0x40"));

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertFalse(subject.matchesCanary(encryptionKeyCanary));
  }

  @Test
  public void matchesCanary_shouldThrowIncorrectKeyException_IfHSMKeyWasWrong() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenThrow(new IllegalBlockSizeException("something bad happened"));

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    try {
      subject.matchesCanary(encryptionKeyCanary);
      fail("Expected IncorrectKeyException, got none");
    } catch (IncorrectKeyException e) {
    } catch (RuntimeException e) {
      fail("Wrong exception. Expected IncorrectKeyException but got " + e.getClass().toString());
    }
  }

  @Test
  public void matchesCanary_shouldThrowIncorrectKeyException_IfExceptionIsThrown() throws Exception {
    when(encryptionProvider.decrypt(any(), any(), any())).thenThrow(new Exception("something bad happened"));

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    try {
      subject.matchesCanary(encryptionKeyCanary);
      fail("Expected IncorrectKeyException, got none");
    } catch (IncorrectKeyException e) {
    } catch (RuntimeException e) {
      fail("Wrong exception. Expected IncorrectKeyException but got " + e.getClass().toString());
    }
  }
}