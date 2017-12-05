package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.service.EncryptionService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.SecureRandom;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RandomSerialNumberGeneratorTest {
  @Test
  public void generate_usesEncryptionServiceRandomNumber() throws Exception {
    EncryptionService encryptionService = mock(EncryptionService.class);
    when(encryptionService.getSecureRandom()).thenReturn(new SecureRandom());
    RandomSerialNumberGenerator subject = new RandomSerialNumberGenerator(encryptionService);

    subject.generate();

    verify(encryptionService).getSecureRandom();
  }
}
