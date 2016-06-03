package io.pivotal.security.repository;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.Secret;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.Slinky;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.matcher.SecretMatcher.equalToSecret;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemorySecretStoreTest {

  @Autowired
  InMemorySecretRepository inMemorySecretRepository;

  {
    Slinky.prepareTestInstance(InMemorySecretStoreTest.class, this);
    InMemorySecretStore subject = new InMemorySecretStore(inMemorySecretRepository);

    it("returns null when the store is empty", () -> {
      Assert.assertNull(subject.get("whatever"));
    });

    describe("after storing a secret", () -> {
      Secret secret = Secret.make("doge", "value");

      beforeEach(() -> {
        subject.set("myspecialkey", secret);
      });

      it("can be retrieved", () -> {
        Assert.assertThat(subject.get("myspecialkey"), equalToSecret(secret));
      });

      it("can be deleted", () -> {
        Assert.assertThat(subject.delete("myspecialkey"), equalToSecret(secret));
        Assert.assertNull(subject.get("myspecialkey"));
      });

      describe("setting a secret with the same name", () -> {
        Secret secret2 = Secret.make("catz", "value");

        beforeEach(() -> {
          subject.set("myspecialkey", secret2);
        });

        it("overrides the stored secret", () -> {
          Assert.assertThat(subject.get("myspecialkey"), equalToSecret(secret2));
        });
      });
    });
  }
}
