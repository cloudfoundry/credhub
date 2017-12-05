package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.util.PasswordKeyProxyFactoryTestImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helper.TestHelper.getBouncyCastleProvider;
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
