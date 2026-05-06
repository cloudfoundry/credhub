package org.cloudfoundry.credhub.services;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.utils.TestPasswordKeyProxyFactory;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

public class PasswordEncryptionServiceTest {
  @Test
  public void createsPasswordBasedKeyProxy() throws Exception {
    final PasswordEncryptionService subject = new PasswordEncryptionService(new TestPasswordKeyProxyFactory());

    final EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionPassword("foobar");

    final KeyProxy keyProxy = subject.createKeyProxy(keyMetadata);
    assertThat(keyProxy, instanceOf(PasswordBasedKeyProxy.class));
  }
}
