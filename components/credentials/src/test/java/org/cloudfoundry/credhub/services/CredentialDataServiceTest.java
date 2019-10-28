package org.cloudfoundry.credhub.services;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repositories.CredentialRepository;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CredentialDataServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  @Autowired
  private CredentialDataService subject;

  @Autowired
  private CredentialRepository credentialRepository;

  @Autowired
  private CEFAuditRecord auditRecord;

  @Test
  public void save_savesTheCredential() {
    final Credential credential = new Credential(CREDENTIAL_NAME);

    assertThat(credentialRepository.count(), equalTo(0L));

    credentialRepository.save(credential);

    assertThat(credentialRepository.count(), equalTo(1L));

    assertThat(
      credentialRepository.findOneByNameIgnoreCase(CREDENTIAL_NAME).getName(),
      equalTo(CREDENTIAL_NAME)
    );
  }

  @Test
  public void save_setsTheUuidOnTheCredential() {
    final Credential credential = credentialRepository.save(new Credential(CREDENTIAL_NAME));

    assertThat(credential.getUuid(), instanceOf(UUID.class));
  }

  @Test
  public void find_whenTheCredentialExists_returnsTheCredential() {
    final Credential credential = new Credential(CREDENTIAL_NAME);
    credentialRepository.save(credential);

    assertThat(subject.find(CREDENTIAL_NAME), equalTo(credential));
  }

  @Test
  public void find_isCaseInsensitive() {
    final Credential credential = new Credential(CREDENTIAL_NAME.toLowerCase());
    credentialRepository.save(credential);

    assertThat(subject.find(CREDENTIAL_NAME.toUpperCase()), equalTo(credential));
  }

  @Test
  public void find_whenTheCredentialDoesNotExist_returnsNull() {
    assertThat(subject.find(CREDENTIAL_NAME), equalTo(null));
  }

  @Test
  public void findByUUID_whenTheCredentialExists_returnsTheCredential() {
    final Credential credential = new Credential(CREDENTIAL_NAME);
    credentialRepository.save(credential);
    assertThat(subject.findByUUID(credential.getUuid()), equalTo(credential));
  }

  @Test
  public void delete_whenTheCredentialExists_deletesTheCredential_andReturnsTrue() {
    credentialRepository.save(new Credential(CREDENTIAL_NAME));

    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(true));
    assertThat(credentialRepository.count(), equalTo(0L));
  }

  @Test
  public void delete_addsToAuditRecord() {
    credentialRepository.save(new Credential(CREDENTIAL_NAME));

    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(true));
    assertThat(auditRecord.getResourceName(), is(CREDENTIAL_NAME));
  }

  @Test
  public void delete_whenTheCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(false));
  }

  @Test
  public void delete_isCaseInsensitive() {
    credentialRepository.save(new Credential(CREDENTIAL_NAME.toUpperCase()));

    assertThat(subject.delete(CREDENTIAL_NAME.toLowerCase()), equalTo(true));
    assertThat(credentialRepository.count(), equalTo(0L));
  }
}
