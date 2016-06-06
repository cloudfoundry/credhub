package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import com.greghaskins.spectrum.SpringSpectrum;
import io.pivotal.security.model.StringSecret;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import static com.greghaskins.spectrum.SpringSpectrum.*;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.core.Is.is;

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemoryStringSecretStoreTest {

  @Autowired
  InMemorySecretRepository inMemorySecretRepository;

  InMemorySecretStore subject;

  {
    beforeEach(() -> {
      subject = new InMemorySecretStore(inMemorySecretRepository);
    });

    it("returns null when the store is empty", () -> {
      Assert.assertNull(subject.get("whatever"));
    });

    describe("after storing a secret", () -> {
      StringSecret stringSecret = StringSecret.make("doge");

      beforeEach(() -> {
        subject.set("myspecialkey", stringSecret);
      });

      it("can be retrieved", () -> {
        Assert.assertThat(subject.get("myspecialkey"), reflectiveEqualTo(stringSecret));
      });

      it("can be deleted", () -> {
        Assert.assertThat(subject.delete("myspecialkey"), is(true));
        Assert.assertNull(subject.get("myspecialkey"));
        Assert.assertThat(subject.delete("myspecialkey"), is(false));
      });

      describe("setting a stringSecret with the same name", () -> {
        StringSecret stringSecret2 = StringSecret.make("catz");

        beforeEach(() -> {
          subject.set("myspecialkey", stringSecret2);
        });

        it("overrides the stored stringSecret", () -> {
          Assert.assertThat(subject.get("myspecialkey"), reflectiveEqualTo(stringSecret2));
        });
      });
    });
  }
}
