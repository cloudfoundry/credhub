package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialNameDataServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  @Autowired
  private CredentialNameDataService subject;

  @Autowired
  private CredentialNameRepository credentialNameRepository;

  @Test
  public void save_savesTheCredentialName() {
    final CredentialName credential = new CredentialName(CREDENTIAL_NAME);

    assertThat(credentialNameRepository.count(), equalTo(0L));

    credentialNameRepository.save(credential);

    assertThat(credentialNameRepository.count(), equalTo(1L));

    assertThat(
        credentialNameRepository.findOneByNameIgnoreCase(CREDENTIAL_NAME).getName(),
        equalTo(CREDENTIAL_NAME)
    );
  }

  @Test
  public void save_setsTheUuidOnTheCredentialName() {
    final CredentialName credential = credentialNameRepository.save(new CredentialName(CREDENTIAL_NAME));

    assertThat(credential.getUuid(), instanceOf(UUID.class));
  }

  @Test
  public void find_whenTheCredentialExists_returnsTheCredentialName() {
    final CredentialName credential = new CredentialName(CREDENTIAL_NAME);
    credentialNameRepository.save(credential);

    assertThat(subject.find(CREDENTIAL_NAME), equalTo(credential));
  }

  @Test
  public void find_isCaseInsensitive() {
    final CredentialName credential = new CredentialName(CREDENTIAL_NAME.toLowerCase());
    credentialNameRepository.save(credential);

    assertThat(subject.find(CREDENTIAL_NAME.toUpperCase()), equalTo(credential));
  }

  @Test
  public void find_prependsTheLeadingSlashIfNecessary() {
    final CredentialName credential = new CredentialName(StringUtils.prependIfMissing(CREDENTIAL_NAME, "/"));
    credentialNameRepository.save(credential);

    assertThat(subject.find(StringUtils.removeStart(CREDENTIAL_NAME, "/")), equalTo(credential));
  }

  @Test
  public void find_whenTheCredentialDoesNotExist_returnsNull() {
    assertThat(subject.find(CREDENTIAL_NAME), equalTo(null));
  }

  @Test
  public void delete_whenTheCredentialExists_deletesTheCredential_andReturnsTrue() {
    credentialNameRepository.save(new CredentialName(CREDENTIAL_NAME));

    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(true));
    assertThat(credentialNameRepository.count(), equalTo(0L));
  }

  @Test
  public void delete_whenTheCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.delete(CREDENTIAL_NAME), equalTo(false));
  }

  @Test
  public void delete_isCaseInsensitive() {
    credentialNameRepository.save(new CredentialName(CREDENTIAL_NAME.toUpperCase()));

    assertThat(subject.delete(CREDENTIAL_NAME.toLowerCase()), equalTo(true));
    assertThat(credentialNameRepository.count(), equalTo(0L));
  }

  @Test
  public void delete_prependsTheLeadingSlashIfNecessary() {
    credentialNameRepository.save(new CredentialName(StringUtils.prependIfMissing(CREDENTIAL_NAME, "/")));

    assertThat(subject.delete(StringUtils.removeStart(CREDENTIAL_NAME, "/")), equalTo(true));
    assertThat(credentialNameRepository.count(), equalTo(0L));
  }
}
