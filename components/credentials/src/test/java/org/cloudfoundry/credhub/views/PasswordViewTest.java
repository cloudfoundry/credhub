package org.cloudfoundry.credhub.views;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PasswordViewTest {

  private PasswordCredentialVersion entity;
  private UUID uuid;
  private Encryptor encryptor;
  private Instant createdAt;
  private JsonNode metadata;

  @BeforeEach
  public void beforeEach() {
    encryptor = mock(Encryptor.class);
    uuid = UUID.randomUUID();
    entity = new PasswordCredentialVersion("/foo");
    entity.setEncryptor(encryptor);
    entity.setUuid(uuid);
    createdAt = Instant.now();
    entity.setVersionCreatedAt(createdAt);
    JsonObjectMapper objectMapper = new JsonObjectMapper();
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }
    entity.setMetadata(metadata);

    when(encryptor.decrypt(any()))
      .thenReturn("fake-plaintext-value");
  }


  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    final PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);
    final Instant createdAtWithoutMillis = Instant.ofEpochSecond(createdAt.getEpochSecond());
    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
      + "\"type\":\"password\","
      + "\"version_created_at\":\"" + createdAtWithoutMillis + "\","
      + "\"id\":\""
      + uuid.toString() + "\",\"name\":\"/foo\","
      + "\"metadata\":{\"name\":\"test\"},"
      + "\"value\":\"fake-plaintext-value\""
      + "}"));
  }

  @Test
  public void itHasVersionCreatedAtInTheView() {
    final Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    final PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void itHasTypeInTheView() {
    final PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("password"));
  }

  @Test
  public void itHadUUIDInTheView() {
    final PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }

  @Test
  public void hasMetadataInTheView() {
    final PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getMetadata(), equalTo(metadata));
  }
}
