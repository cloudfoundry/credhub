package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.repository.SecretRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.time.Instant;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class StringSecretTest {
  private StringSecret subject;

  private NamedValueSecret entity;

  @Autowired
  SecretRepository secretRepository;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new StringSecret("value", "myFavoriteValue");
      entity = new NamedValueSecret(uniquify("foo"));
    });

    describe("generating view", () -> {
      it("can create view from entity", () -> {
        entity.setValue("my-value");
        StringSecret actual = subject.generateView(entity);

        assertThat(json(subject), equalTo(json(actual)));
      });

      it("has updated_at in the view", () -> {
        Instant now = Instant.now();
        entity.setValue("my-value")
            .setUpdatedAt(now);

        StringSecret actual = subject.generateView(entity);

        assertThat(actual.getUpdatedAt(), equalTo(now));
      });

      it("has type in the view", () -> {
        StringSecret actual = subject.generateView(entity);

        assertThat(actual.getType(), equalTo("value"));
      });

      it("has a uuid in the view", () -> {
        entity.setValue("my-value");
        entity = secretRepository.save(entity);

        StringSecret actual = subject.generateView(entity);

        assertThat(actual.getUuid(), notNullValue());
      });
    });
  }
}