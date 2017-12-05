package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialDataServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final String CREDENTIAL_NAME2 = "/test/credential2";

  @Autowired
  private CredentialDataService subject;

  @Autowired
  private CredentialRepository credentialRepository;

  @Test
  public void save_savesTheCredentialName() {
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
  public void save_setsTheUuidOnTheCredentialName() {
    final Credential credential = credentialRepository.save(new Credential(CREDENTIAL_NAME));

    assertThat(credential.getUuid(), instanceOf(UUID.class));
  }

  @Test
  public void find_whenTheCredentialExists_returnsTheCredentialName() {
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
  public void delete_whenTheCredentialExists_deletesTheCredential_andReturnsTrue() {
    credentialRepository.save(new Credential(CREDENTIAL_NAME));

    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(true));
    assertThat(credentialRepository.count(), equalTo(0L));
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

  @Test
  public void findAll_whenThereAreNoCredentials_returnsAnEmptyList() {
    assertThat(subject.findAll().isEmpty(), equalTo(true));
  }

  @Test
  public void findAll_whenThereAreCredentials_returnsTheListOfNames() {
    credentialRepository.save(new Credential(CREDENTIAL_NAME));
    credentialRepository.save(new Credential(CREDENTIAL_NAME2));

    List<Credential> credentials = subject.findAll();
    List<String> names = credentials.stream()
        .map(Credential::getName)
        .collect(Collectors.toList());

    assertThat(names, hasSize(2));
    assertThat(names, containsInAnyOrder(CREDENTIAL_NAME, CREDENTIAL_NAME2));
  }
}
