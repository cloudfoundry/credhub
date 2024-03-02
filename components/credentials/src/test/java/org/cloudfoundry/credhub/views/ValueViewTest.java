package org.cloudfoundry.credhub.views;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ValueViewTest {

  private ValueCredentialVersion entity;
  private UUID uuid;
  private Encryptor encryptor;
  private Instant createdAt;
  private JsonNode metadata;

  @BeforeEach
  public void beforeEach() {
    uuid = UUID.randomUUID();
    encryptor = mock(Encryptor.class);
    when(encryptor.decrypt(any()))
      .thenReturn("fake-plaintext-value");
    entity = new ValueCredentialVersion("/foo");
    entity.setEncryptor(encryptor);
    entity.setUuid(uuid);
    JsonObjectMapper objectMapper = new JsonObjectMapper();
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }
    entity.setMetadata(metadata);
    createdAt = Instant.now();
    entity.setVersionCreatedAt(createdAt);
  }

  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    final Instant createdAtWithoutMillis = Instant.ofEpochSecond(createdAt.getEpochSecond());
    final ValueView actual = (ValueView) ValueView.fromEntity(entity);
    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
      + "\"type\":\"value\","
      + "\"version_created_at\":\"" + createdAtWithoutMillis + "\","
      + "\"id\":\""
      + uuid.toString() + "\",\"name\":\"/foo\","
      + "\"metadata\":{\"name\":\"test\"},"
      + "\"value\":\"fake-plaintext-value\""
      + "}"));
  }

  @Test
  public void hasVersionCreateAtInTheView() {
    final Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    final ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void hasTypeInTheView() {
    final ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("value"));
  }

  @Test
  public void hasAUUIDInTheView() {
    final ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }

  @Test
  public void hasMetadataInTheView() {
    final ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getMetadata(), equalTo(metadata));
  }
}
