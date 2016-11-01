package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedValueSecret;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.time.Instant;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class StringSecretTest {

  @Autowired
  SecretDataService secretDataService;

  private NamedValueSecret entity;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      entity = new NamedValueSecret("foo");
    });

    it("can create view from entity", () -> {
      entity.setValue("my-value");
      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);
      assertThat(json(actual), equalTo("{" +
          "\"type\":\"value\"," +
          "\"updated_at\":null," +
          "\"id\":null," +
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
      entity = (NamedValueSecret) secretDataService.save(entity);

      StringSecret actual = (StringSecret) StringSecret.fromEntity(entity);

      assertThat(actual.getUuid(), notNullValue());
    });
  }
}
