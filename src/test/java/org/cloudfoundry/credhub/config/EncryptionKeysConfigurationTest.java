package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class EncryptionKeysConfigurationTest {

  @Autowired
  private EncryptionKeysConfiguration subject;

  @Test
  public void fillsTheListOfKeysFromApplicationYml() {
    List<EncryptionKeyMetadata> keys = subject.getKeys();
    assertThat(keys.size(), equalTo(2));

    EncryptionKeyMetadata firstKey = keys.get(0);
    EncryptionKeyMetadata secondKey = keys.get(1);

    assertThat(firstKey.getEncryptionPassword(), equalTo("opensesame"));
    assertThat(firstKey.isActive(), equalTo(true));

    assertThat(secondKey.getEncryptionPassword(), equalTo("correcthorsebatterystaple"));
    assertThat(secondKey.isActive(), equalTo(false));
  }
}
