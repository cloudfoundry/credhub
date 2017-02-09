package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class StringViewTest {
  @MockBean
  SecretEncryptionHelper secretEncryptionHelper;

  private NamedValueSecret entity;

  private UUID uuid;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      uuid = UUID.randomUUID();
      entity = new NamedValueSecret("foo")
        .setUuid(uuid);
      entity.setEncryptedValue("fake-encrypted-value".getBytes());
      entity.setNonce("fake-nonce".getBytes());

      when(secretEncryptionHelper.retrieveClearTextValue(any(NamedValueSecretData.class))).thenReturn("fake-plaintext-value");
    });

    it("can create view from entity", () -> {
      StringView actual = (StringView) StringView.fromEntity(entity);
      assertThat(json(actual), equalTo("{" +
          "\"type\":\"value\"," +
          "\"version_created_at\":null," +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"name\":\"foo\"," +
          "\"value\":\"fake-plaintext-value\"" +
          "}"));
    });

    it("has version_created_at in the view", () -> {
      Instant now = Instant.now();
      entity.setVersionCreatedAt(now);

      StringView actual = (StringView) StringView.fromEntity(entity);

      assertThat(actual.getVersionCreatedAt(), equalTo(now));
    });

    it("has type in the view", () -> {
      StringView actual = (StringView) StringView.fromEntity(entity);

      assertThat(actual.getType(), equalTo("value"));
    });

    it("has a uuid in the view", () -> {
      StringView actual = (StringView) StringView.fromEntity(entity);

      assertThat(actual.getUuid(), equalTo(uuid.toString()));
    });
  }
}
