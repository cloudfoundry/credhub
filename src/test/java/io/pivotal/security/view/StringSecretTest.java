package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.time.Instant;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class StringSecretTest {
  private StringSecret subject;

  private NamedStringSecret entity;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new StringSecret("myFavoriteValue");
      entity = new NamedStringSecret(uniquify("foo"));
    });

    it("populates entity with all values", () -> {
      subject.populateEntity(entity);
      assertThat(entity.getValue(), equalTo("myFavoriteValue"));
    });

    describe("generating view", () -> {
      it("can create view from entity", () -> {
        entity.setValue("my-value");
        StringSecret actual = subject.generateView(entity);

        assertThat(json(subject), equalTo(json(actual)));
      });

      it("generated view has updated at", () -> {
        Instant now = Instant.now();
        entity.setValue("my-value")
            .setUpdatedAt(now);

        StringSecret actual = subject.generateView(entity);

        assertThat(actual.getUpdatedAt(), equalTo(now));
      });
    });
  }
}