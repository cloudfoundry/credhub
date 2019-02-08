package org.cloudfoundry.credhub.entities;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.repositories.EncryptionKeyCanaryRepository;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@SpringBootTest(classes = CredhubTestApp.class)
public class UuidGeneratorTest {

  @Autowired
  private EncryptionKeyCanaryRepository repository;

  @Test
  public void generate_ifNoUUIDSet_itGeneratesAUUID() {
    final EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    assertNull(encryptionKeyCanary.getUuid());

    final EncryptionKeyCanary savedCanary = repository.saveAndFlush(encryptionKeyCanary);
    assertNotNull(savedCanary.getUuid());
  }

  @Test
  public void generate_ifUUIDSet_itKeepsUUID() {
    final EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    final UUID uuid = UUID.randomUUID();
    encryptionKeyCanary.setUuid(uuid);

    final EncryptionKeyCanary savedCanary = repository.saveAndFlush(encryptionKeyCanary);
    assertThat(savedCanary.getUuid(), equalTo(uuid));
  }
}
