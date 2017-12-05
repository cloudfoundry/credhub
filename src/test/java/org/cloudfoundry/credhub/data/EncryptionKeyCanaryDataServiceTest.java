package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class EncryptionKeyCanaryDataServiceTest {

  @Autowired
  EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  EncryptionKeyCanaryDataService subject;

  @Before
  public void beforeEach() {
    encryptionKeyCanaryRepository.deleteAllInBatch();
    subject = new EncryptionKeyCanaryDataService(encryptionKeyCanaryRepository);
  }

  @Test
  public void save_savesTheEncryptionCanary() {
    EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    encryptionKeyCanary.setNonce("test-nonce".getBytes());
    encryptionKeyCanary.setEncryptedCanaryValue("test-value".getBytes());
    subject.save(encryptionKeyCanary);

    List<EncryptionKeyCanary> canaries = subject.findAll();

    assertThat(canaries, hasSize(1));

    EncryptionKeyCanary actual = canaries.get(0);

    assertNotNull(actual.getUuid());
    assertThat(actual.getUuid(), equalTo(encryptionKeyCanary.getUuid()));
    assertThat(actual.getNonce(), equalTo("test-nonce".getBytes()));
    assertThat(actual.getEncryptedCanaryValue(), equalTo("test-value".getBytes()));
  }

  @Test
  public void findAll_whenThereAreNoCanaries_returnsEmptyList() {
    assertThat(subject.findAll(), hasSize(0));
  }

  @Test
  public void findAll_whenThereAreCanaries_returnsCanariesAsAList() {

    EncryptionKeyCanary firstCanary = new EncryptionKeyCanary();
    EncryptionKeyCanary secondCanary = new EncryptionKeyCanary();

    subject.save(firstCanary);
    subject.save(secondCanary);

    List<EncryptionKeyCanary> canaries = subject.findAll();
    List<UUID> uuids = canaries.stream().map(canary -> canary.getUuid())
        .collect(Collectors.toList());

    assertThat(canaries, hasSize(2));
    assertThat(uuids, containsInAnyOrder(firstCanary.getUuid(), secondCanary.getUuid()));
  }

  @Test
  public void delete_whenThereAreCanaries_deletesTheRequestedCanaries() {
    EncryptionKeyCanary firstCanary = new EncryptionKeyCanary();
    EncryptionKeyCanary secondCanary = new EncryptionKeyCanary();
    EncryptionKeyCanary thirdCanary = new EncryptionKeyCanary();

    firstCanary = subject.save(firstCanary);
    secondCanary = subject.save(secondCanary);
    thirdCanary = subject.save(thirdCanary);

    List<EncryptionKeyCanary> canaries = subject.findAll();

    List<UUID> uuids = canaries.stream().map(canary -> canary.getUuid())
        .collect(Collectors.toList());

    assertThat(canaries, hasSize(3));
    assertThat(uuids, containsInAnyOrder(firstCanary.getUuid(), secondCanary.getUuid(), thirdCanary.getUuid()));

    subject.delete(newArrayList(firstCanary.getUuid(), thirdCanary.getUuid()));

    canaries = subject.findAll();
    uuids = canaries.stream().map(canary -> canary.getUuid())
        .collect(Collectors.toList());

    assertThat(canaries, hasSize(1));
    assertThat(uuids, containsInAnyOrder(secondCanary.getUuid()));
  }

  @Test
  public void delete_whenThereAreNoCanaries_doesNothing() {
    assertThat(subject.findAll(), hasSize(0));

    subject.delete(newArrayList(UUID.randomUUID()));

    assertThat(subject.findAll(), hasSize(0));
  }
}
