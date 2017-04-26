package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialNameAspectTest {
  @Autowired
  CredentialNameRepository credentialNameRepository;

  @Before
  public void setup() {
    credentialNameRepository.save(new CredentialName("/test/name"));
  }

  @Test
  public void save_prependsLeadingSlashToCredentialNameIfMissing() {
    CredentialName savedCredential = credentialNameRepository
        .save(new CredentialName("new/name"));
    assertThat(savedCredential.getName(), equalTo("/new/name"));
  }

  @Test
  public void saveAndFlush_prependsLeadingSlashToCredentialNameIfMissing() {
    CredentialName savedCredential = credentialNameRepository
        .saveAndFlush(new CredentialName("new/name"));
    assertThat(savedCredential.getName(), equalTo("/new/name"));
  }

  @Test
  public void findOneByNameIgnoreCase_prependsLeadingSlashToCredentialNameIfMissing() {
    CredentialName foundCredentialName = credentialNameRepository
        .findOneByNameIgnoreCase("test/name");
    assertThat(foundCredentialName, notNullValue());
    assertThat(foundCredentialName.getName(), equalTo("/test/name"));
  }

  @Test
  public void deleteByNameIgnoreCase_prependsLeadingSlashToCredentialNameIfMissing() {
    long numberOfDeletedRecords = credentialNameRepository
        .deleteByNameIgnoreCase("test/name");
    assertThat(numberOfDeletedRecords, equalTo(1L));
  }
}
