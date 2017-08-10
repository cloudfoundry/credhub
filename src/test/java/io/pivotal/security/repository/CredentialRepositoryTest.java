package io.pivotal.security.repository;

import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestDatabase.Replace;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class CredentialRepositoryTest {

  @Autowired
  CredentialRepository subject;

  @Autowired
  CredentialNameRepository credentialNameRepository;

  @Autowired
  EncryptionKeyCanaryRepository canaryRepository;

  private String name;
  private UUID canaryUuid;

  @Before
  public void beforeEach() {
    name = "my-credential";
    EncryptionKeyCanary canary = canaryRepository.save(new EncryptionKeyCanary());
    canaryUuid = canary.getUuid();
  }

  @Test
  public void canSaveCertificatesOfLength7000WhichMeans7016ForGCM() {
    byte[] encryptedValue = new byte[7016];
    Arrays.fill(encryptedValue, (byte) 'A');
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);

    CredentialName credentialName = credentialNameRepository.save(new CredentialName(name));
    final String longString = stringBuilder.toString();

    CertificateCredentialData entity = new CertificateCredentialData();
    entity.setCredentialName(credentialName);
    entity.setCa(longString);
    entity.setCertificate(longString);
    entity.setEncryptedValue(encryptedValue);
    entity.setEncryptionKeyUuid(canaryUuid);

    subject.save(entity);
    CertificateCredentialData credentialData = (CertificateCredentialData) subject
        .findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(credentialName.getUuid());
    assertThat(credentialData.getCa().length(), equalTo(7000));
    assertThat(credentialData.getCertificate().length(), equalTo(7000));
    assertThat(credentialData.getEncryptedValue(), equalTo(encryptedValue));
    assertThat(credentialData.getEncryptedValue().length, equalTo(7016));
  }

  @Test
  public void canSaveStringsOfLength7000WhichMeans7016ForGCM() {
    byte[] encryptedValue = new byte[7016];
    Arrays.fill(encryptedValue, (byte) 'A');

    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    ValueCredentialData entity = new ValueCredentialData();
    CredentialName credentialName = credentialNameRepository.save(new CredentialName(name));
    entity.setCredentialName(credentialName);
    entity.setEncryptedValue(encryptedValue);
    entity.setEncryptionKeyUuid(canaryUuid);

    subject.save(entity);
    assertThat(subject.findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(credentialName.getUuid())
        .getEncryptedValue().length, equalTo(7016));
  }
}
