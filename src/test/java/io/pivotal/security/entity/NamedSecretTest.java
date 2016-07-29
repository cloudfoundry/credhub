package io.pivotal.security.entity;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Transactional
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class NamedSecretTest {
  @Autowired
  @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;
  @Autowired
  SecretRepository repository;
  private final ZoneId utc = ZoneId.of("UTC");
  private NamedCertificateSecret secret;
  private LocalDateTime frozenTime;

  @Before
  public void setUp() throws Exception {
    freeze();
    secret = io.pivotal.security.entity.NamedCertificateSecret.make("foo", "ca", "pub", "priv");
  }

  private void freeze() {
    frozenTime = LocalDateTime.now(utc);
    currentTimeProvider.setOverrideTime(frozenTime);
  }

  @After
  public void tearDown() throws Exception {
    currentTimeProvider.reset();
  }

  @Test
  public void returnsDateCreated() throws Exception {
    repository.save(secret);
    assertThat(repository.findOneByName("foo").getUpdatedAt(), equalTo(frozenTime));
  }

  @Test
  public void returnsDateUpdated() {
    secret = repository.save(secret);
    freeze();
    secret.setPrivateKey("new-priv");  // Change object so that Hibernate will update the database
    secret = repository.save(secret);
    assertThat(repository.findOneByName("foo").getUpdatedAt(), equalTo(frozenTime));
  }
}