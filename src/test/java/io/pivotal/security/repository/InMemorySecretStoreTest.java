package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.Secret;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static io.pivotal.security.matcher.SecretMatcher.equalToSecret;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemorySecretStoreTest {

  @Autowired
  InMemorySecretRepository inMemorySecretRepository;

  private InMemorySecretStore subject;

  @Before
  public void setup() {
    this.subject = new InMemorySecretStore(inMemorySecretRepository);
  }

  @Test
  public void testGetReturnsNull() {
    Assert.assertNull(subject.get("whatever"));
  }

  @Test
  public void testReturnsStoredSecret() {
    Secret secret = Secret.make("doge", "value");

    subject.set("myspecialkey", secret);

    Assert.assertThat(subject.get("myspecialkey"), equalToSecret(secret));
  }

  @Test
  public void testOverridesStoredSecret() {
    Secret secret1 = Secret.make("doges", "value");

    subject.set("myspecialkey", secret1);

    Secret secret2 = Secret.make("catz", "value");

    subject.set("myspecialkey", secret2);

    Assert.assertThat(subject.get("myspecialkey"), equalToSecret(secret2));
  }

  @Test
  public void testRemovesStoredSecret() {
    Secret secret = Secret.make("doges", "value");

    subject.set("myspecialkey", secret);

    Assert.assertThat(subject.delete("myspecialkey"), equalToSecret(secret));

    Assert.assertNull(subject.get("myspecialkey"));
  }
}
