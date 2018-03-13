package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyProvider;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.config.ProviderType;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class EncryptionProviderFactoryTest {
  @Mock
  private EncryptionKeyProvider provider;

  @Before
  public void setUp(){
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void getEncryptionService_whenEncryptionServiceIsAlreadyInitialized() throws Exception {
    EncryptionProviderFactory subject = new EncryptionProviderFactory(
        mock(EncryptionKeysConfiguration.class),
        mock(TimedRetry.class),
        mock(PasswordKeyProxyFactory.class)
    );

    when(provider.getProviderType()).thenReturn(ProviderType.INTERNAL);

    InternalEncryptionService internal = (InternalEncryptionService) subject.getEncryptionService(provider);
    InternalEncryptionService internalAgain = (InternalEncryptionService) subject.getEncryptionService(provider);
    assertThat(internal, sameInstance(internalAgain));
    assertThat(internal, instanceOf(PasswordEncryptionService.class));
  }


}
