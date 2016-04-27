package io.pivotal.security.repository;

import io.pivotal.security.entity.Secret;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

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
        Map<String, String> values = new HashMap<>();
        values.put("doges", "foo");
        Secret secret = new Secret(values);

        subject.set("myspecialkey", secret);

        Assert.assertEquals(subject.get("myspecialkey"), secret);
    }

    @Test
    public void testOverridesStoredSecret() {
        Map<String, String> values1 = new HashMap<>();
        values1.put("doges", "foo");
        Secret secret1 = new Secret(values1);

        subject.set("myspecialkey", secret1);

        Map<String, String> values2 = new HashMap<>();
        values2.put("cates", "foo");
        Secret secret2 = new Secret(values2);

        subject.set("myspecialkey", secret2);

        Assert.assertEquals(subject.get("myspecialkey"), secret2);
    }

    @Test
    public void testRemovesStoredSecret() {
        Map<String, String> values = new HashMap<>();
        values.put("doges", "foo");
        Secret secret = new Secret(values);

        subject.set("myspecialkey", secret);

        Assert.assertEquals(subject.delete("myspecialkey"), secret);

        Assert.assertNull(subject.get("myspecialkey"));
    }
}
