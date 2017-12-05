package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.serializeToString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class JsonViewTest {

  private JsonCredentialVersion entity;
  private UUID uuid;
  private Encryptor encryptor;
  private Map<String, Object> value;
  private String serializedValue;

  @Before
  public void beforeEach() {
    value = new HashMap<>();
    value.put("string", "something");
    value.put("num", 10);
    value.put("camelCase", "blabla");

    serializedValue = serializeToString(value);

    encryptor = mock(Encryptor.class);
    uuid = UUID.randomUUID();
    entity = new JsonCredentialVersion("/foo")
        .setEncryptor(encryptor)
        .setUuid(uuid);

    when(encryptor.decrypt(any()))
        .thenReturn(serializedValue);
  }

  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    JsonView actual = (JsonView) JsonView.fromEntity(entity);
    assertThat(serializeToString(actual), equalTo("{"
        + "\"type\":\"json\","
        + "\"version_created_at\":null,"
        + "\"id\":\"" + uuid.toString() + "\","
        + "\"name\":\"/foo\","
        + "\"value\":" + serializedValue
        + "}"));
  }

  @Test
  public void hasVersionCreatedAtInTheView() {
    Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void hasTypeInTheView() {
    JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("json"));
  }

  @Test
  public void hasAUUIDInTheView() {
    JsonView actual = (JsonView) JsonView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }
}
