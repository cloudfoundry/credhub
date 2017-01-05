package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class StringSecretTest {

  private NamedValueSecret entity;

  private UUID uuid;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      uuid = UUID.randomUUID();
      entity = new NamedValueSecret("foo")
        .setUuid(uuid);
    });

    it("can create view from entity", () -> {
      entity.setValue("my-value");
      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);
      assertThat(json(actual), equalTo("{" +
          "\"type\":\"value\"," +
          "\"updated_at\":null," +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"name\":\"foo\"," +
          "\"value\":\"my-value\"" +
          "}"));
    });

    it("has updated_at in the view", () -> {
      Instant now = Instant.now();
      entity.setValue("my-value");
      entity.setUpdatedAt(now);

      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);

      assertThat(actual.getUpdatedAt(), equalTo(now));
    });

    it("has type in the view", () -> {
      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);

      assertThat(actual.getType(), equalTo("value"));
    });

    it("has a uuid in the view", () -> {
      entity.setValue("my-value");

      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);

      assertThat(actual.getUuid(), equalTo(uuid.toString()));
    });
  }
}
