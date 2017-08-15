package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.util.PasswordKeyProxyFactoryTestImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(JUnit4.class)
public class BcEncryptionServiceTest {
  @Test
  public void createsPasswordBasedKeyProxy() throws Exception {
    BcEncryptionService subject = new BcEncryptionService(getBouncyCastleProvider(), new PasswordKeyProxyFactoryTestImpl());

    EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionPassword("foobar");

    final KeyProxy keyProxy = subject.createKeyProxy(keyMetadata);
    assertThat(keyProxy, instanceOf(PasswordBasedKeyProxy.class));
  }
}
