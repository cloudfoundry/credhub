package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class ValueViewTest {

  private ValueCredentialVersion entity;

  private UUID uuid;

  private Encryptor encryptor;

  @Before
  public void beforeEach() {
    uuid = UUID.randomUUID();
    encryptor = mock(Encryptor.class);
    when(encryptor.decrypt(any()))
        .thenReturn("fake-plaintext-value");
    entity = new ValueCredentialVersion("/foo")
        .setEncryptor(encryptor)
        .setUuid(uuid);
  }

  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    ValueView actual = (ValueView) ValueView.fromEntity(entity);
    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
        + "\"type\":\"value\","
        + "\"version_created_at\":null,"
        + "\"id\":\""
        + uuid.toString() + "\",\"name\":\"/foo\","
        + "\"value\":\"fake-plaintext-value\""
        + "}"));
  }

  @Test
  public void hasVersionCreateAtInTheView() {
    Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void hasTypeInTheView() {
    ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("value"));
  }

  @Test
  public void hasAUUIDInTheView() {
    ValueView actual = (ValueView) ValueView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }
}
