package io.pivotal.security.repository;

import io.pivotal.security.entity.Secret;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class InMemorySecretRepositoryTest {

  private InMemorySecretRepository subject;

  @Before
  public void setup() {
    this.subject = new InMemorySecretRepository();
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
