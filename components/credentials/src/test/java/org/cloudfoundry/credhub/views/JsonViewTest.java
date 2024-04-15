package org.cloudfoundry.credhub.views;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.serializeToString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JsonViewTest {

  private JsonCredentialVersion entity;
  private UUID uuid;
  private Encryptor encryptor;
  private Map<String, Object> value;
  private String serializedValue;
  private Instant createdAt;
  private JsonNode metadata;

  @BeforeEach
  public void beforeEach() {
    value = new HashMap<>();
    value.put("string", "something");
    value.put("num", 10);
    value.put("camelCase", "blabla");

    serializedValue = serializeToString(value);

    encryptor = mock(Encryptor.class);
    uuid = UUID.randomUUID();
    entity = new JsonCredentialVersion("/foo");
    entity.setEncryptor(encryptor);
    entity.setUuid(uuid);
    JsonObjectMapper objectMapper = new JsonObjectMapper();
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }
    entity.setMetadata(metadata);
    when(encryptor.decrypt(any()))
      .thenReturn(serializedValue);
    createdAt = Instant.now();
    entity.setVersionCreatedAt(createdAt);
  }

  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    final Instant createdAtWithoutMillis = Instant.ofEpochSecond(createdAt.getEpochSecond());
    final JsonView actual = (JsonView) JsonView.fromEntity(entity);
    assertThat(serializeToString(actual), equalTo("{"
      + "\"type\":\"json\","
      + "\"version_created_at\":\"" + createdAtWithoutMillis + "\","
      + "\"id\":\"" + uuid.toString() + "\","
      + "\"name\":\"/foo\","
      + "\"metadata\":{\"name\":\"test\"},"
      + "\"value\":" + serializedValue
      + "}"));
  }

  @Test
  public void hasVersionCreatedAtInTheView() {
    final Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    final JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void hasTypeInTheView() {
    final JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("json"));
  }

  @Test
  public void hasAUUIDInTheView() {
    final JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }

  @Test
  public void hasMetadataInTheView() {
    final JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getMetadata(), equalTo(metadata));
  }
}
