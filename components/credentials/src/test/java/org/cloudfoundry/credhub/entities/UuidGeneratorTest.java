package org.cloudfoundry.credhub.entities;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.repositories.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

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
