package org.cloudfoundry.credhub.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@ExtendWith(SpringExtension.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class EncryptionKeysConfigurationTest {

  @Autowired
  private EncryptionKeysConfiguration subject;

  @Test
  public void fillsTheListOfKeysFromApplicationYml() {
    final List<EncryptionKeyMetadata> keys = subject.getProviders().get(0).getKeys();
    assertThat(keys.size(), equalTo(2));

    final EncryptionKeyMetadata firstKey = keys.get(0);
    final EncryptionKeyMetadata secondKey = keys.get(1);

    assertThat(firstKey.getEncryptionPassword(), equalTo("opensesame"));
    assertThat(firstKey.isActive(), equalTo(true));

    assertThat(secondKey.getEncryptionPassword(), equalTo("correcthorsebatterystaple"));
    assertThat(secondKey.isActive(), equalTo(false));
  }

  @Test
  public void fillsTheConfigurationObject() {
    final EncryptionConfiguration config = subject.getProviders().get(0).getConfiguration();
    assertThat(config.getHost(), equalTo("localhost"));
    assertThat(config.getPort(), equalTo(50051));
  }
}
