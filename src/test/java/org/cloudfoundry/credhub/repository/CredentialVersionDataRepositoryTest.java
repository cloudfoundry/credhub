package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class CredentialVersionDataRepositoryTest {

  @Autowired
  CredentialVersionRepository subject;

  @Autowired
  CredentialRepository credentialRepository;

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

    Credential credential = credentialRepository.save(new Credential(name));
    final String longString = stringBuilder.toString();

    CertificateCredentialVersionData entity = new CertificateCredentialVersionData();
    entity.setCredential(credential);
    entity.setCa(longString);
    entity.setCertificate(longString);
    entity.setEncryptedValueData(new EncryptedValue()
        .setEncryptionKeyUuid(canaryUuid)
        .setEncryptedValue(encryptedValue)
        .setNonce("nonce".getBytes()));

    subject.save(entity);
    CertificateCredentialVersionData credentialData = (CertificateCredentialVersionData) subject
        .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid());
    assertThat(credentialData.getCa().length(), equalTo(7000));
    assertThat(credentialData.getCertificate().length(), equalTo(7000));
    assertThat(credentialData.getEncryptedValueData().getEncryptedValue(), equalTo(encryptedValue));
    assertThat(credentialData.getEncryptedValueData().getEncryptedValue().length, equalTo(7016));
  }

  @Test
  public void canSaveStringsOfLength7000WhichMeans7016ForGCM() {
    byte[] encryptedValue = new byte[7016];
    Arrays.fill(encryptedValue, (byte) 'A');

    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    ValueCredentialVersionData entity = new ValueCredentialVersionData();
    Credential credential = credentialRepository.save(new Credential(name));
    entity.setCredential(credential);
    entity.setEncryptedValueData(new EncryptedValue()
      .setEncryptedValue(encryptedValue)
      .setEncryptionKeyUuid(canaryUuid)
      .setNonce("nonce".getBytes()));

    subject.save(entity);
    assertThat(subject.findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
        .getEncryptedValueData().getEncryptedValue().length, equalTo(7016));
  }
}
