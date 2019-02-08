package org.cloudfoundry.credhub.services;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.exceptions.IncorrectKeyException;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    when(encryptionKeyCanary.getEncryptedCanaryValue()).thenReturn("value".getBytes(StringUtil.UTF_8));
    when(encryptionKeyCanary.getNonce()).thenReturn("nonce".getBytes(StringUtil.UTF_8));
    when(encryptionKeyMetadata.getEncryptionKeyName()).thenReturn("name");
    when(encryptionProvider.decrypt(any(), any(), any())).thenReturn(EncryptionKeyCanaryMapper.CANARY_VALUE);

    subject = new ExternalKeyProxy(encryptionKeyMetadata, encryptionProvider);
    assertTrue(subject.matchesCanary(encryptionKeyCanary));

    final ArgumentCaptor<EncryptionKey> argument = ArgumentCaptor.forClass(EncryptionKey.class);
    verify(encryptionProvider).decrypt(argument.capture(), eq("value".getBytes(StringUtil.UTF_8)), eq("nonce".getBytes(StringUtil.UTF_8)));
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
    } catch (final IncorrectKeyException e) {
    } catch (final RuntimeException e) {
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
    } catch (final IncorrectKeyException e) {
    } catch (final RuntimeException e) {
      fail("Wrong exception. Expected IncorrectKeyException but got " + e.getClass().toString());
    }
  }
}
