package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.ValueCredential;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class ValueViewTest {

  private ValueCredential entity;

  private UUID uuid;

  private Encryptor encryptor;

  {
    beforeEach(() -> {
      uuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      when(encryptor.decrypt(any()))
          .thenReturn("fake-plaintext-value");
      entity = new ValueCredential("/foo")
          .setEncryptor(encryptor)
          .setUuid(uuid);
    });

    it("can create view from entity", () -> {
      ValueView actual = (ValueView) ValueView.fromEntity(entity);
      assertThat(json(actual), equalTo("{"
          + "\"type\":\"value\","
          + "\"version_created_at\":null,"
          + "\"id\":\""
          + uuid.toString() + "\",\"name\":\"/foo\","
          + "\"value\":\"fake-plaintext-value\""
          + "}"));
    });

    it("has version_created_at in the view", () -> {
      Instant now = Instant.now();
      entity.setVersionCreatedAt(now);

      ValueView actual = (ValueView) ValueView.fromEntity(entity);

      assertThat(actual.getVersionCreatedAt(), equalTo(now));
    });

    it("has type in the view", () -> {
      ValueView actual = (ValueView) ValueView.fromEntity(entity);

      assertThat(actual.getType(), equalTo("value"));
    });

    it("has a uuid in the view", () -> {
      ValueView actual = (ValueView) ValueView.fromEntity(entity);

      assertThat(actual.getUuid(), equalTo(uuid.toString()));
    });
  }
}
