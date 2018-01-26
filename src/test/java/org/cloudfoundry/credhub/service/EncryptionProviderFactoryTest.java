package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.config.LunaProviderProperties;
import org.cloudfoundry.credhub.config.ProviderType;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(JUnit4.class)
public class EncryptionProviderFactoryTest {

  @Test
  public void getEncryptionService_whenEncryptionServiceIsAlreadyInitialized() throws Exception {
    EncryptionProviderFactory subject = new EncryptionProviderFactory(
        mock(EncryptionKeysConfiguration.class),
        mock(LunaProviderProperties.class),
        mock(TimedRetry.class),
        mock(PasswordKeyProxyFactory.class)
    );

    EncryptionService internal = subject.getEncryptionService(ProviderType.INTERNAL);
    EncryptionService internalAgain = subject.getEncryptionService(ProviderType.INTERNAL);
    assertThat(internal, sameInstance(internalAgain));
    assertThat(internal, instanceOf(InternalEncryptionService.class));
  }


}
