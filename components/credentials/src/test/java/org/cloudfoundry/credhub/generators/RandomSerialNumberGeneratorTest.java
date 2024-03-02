package org.cloudfoundry.credhub.generators;

import java.security.SecureRandom;

import org.cloudfoundry.credhub.services.RandomNumberGenerator;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RandomSerialNumberGeneratorTest {
  @Test
  public void generate_usesEncryptionServiceRandomNumber() throws Exception {
    final RandomNumberGenerator randomNumberGenerator = mock(RandomNumberGenerator.class);
    when(randomNumberGenerator.getSecureRandom()).thenReturn(new SecureRandom());
    final RandomSerialNumberGenerator subject = new RandomSerialNumberGenerator(randomNumberGenerator);

    subject.generate();

    verify(randomNumberGenerator).getSecureRandom();
  }
}
