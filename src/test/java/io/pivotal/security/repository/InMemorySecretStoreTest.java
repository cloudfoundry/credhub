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
    Secret secret = new Secret("doge", "value");

    subject.set("myspecialkey", secret);

    Assert.assertEquals(subject.get("myspecialkey"), secret);
  }

  @Test
  public void testOverridesStoredSecret() {
    Secret secret1 = new Secret("doges", "value");

    subject.set("myspecialkey", secret1);

    Secret secret2 = new Secret("catz", "value");

    subject.set("myspecialkey", secret2);

    Assert.assertEquals(subject.get("myspecialkey"), secret2);
  }

  @Test
  public void testRemovesStoredSecret() {
    Secret secret = new Secret("doges", "value");

    subject.set("myspecialkey", secret);

    Assert.assertEquals(subject.delete("myspecialkey"), secret);

    Assert.assertNull(subject.get("myspecialkey"));
  }
}
