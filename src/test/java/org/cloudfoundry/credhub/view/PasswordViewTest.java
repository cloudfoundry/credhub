package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
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
public class PasswordViewTest {

  private PasswordCredentialVersion entity;
  private UUID uuid;
  private Encryptor encryptor;

  @Before
  public void beforeEach() {
    encryptor = mock(Encryptor.class);
    uuid = UUID.randomUUID();
    entity = new PasswordCredentialVersion("/foo")
        .setEncryptor(encryptor)
        .setUuid(uuid);

    when(encryptor.decrypt(any()))
        .thenReturn("fake-plaintext-value");
  }


  @Test
  public void itCanCreateViewFromEntity() throws IOException {
    PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);
    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
        + "\"type\":\"password\","
        + "\"version_created_at\":null,"
        + "\"id\":\""
        + uuid.toString() + "\",\"name\":\"/foo\","
        + "\"value\":\"fake-plaintext-value\""
        + "}"));
  }

  @Test
  public void itHasVersionCreatedAtInTheView() {
    Instant now = Instant.now();
    entity.setVersionCreatedAt(now);

    PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void itHasTypeInTheView() {
    PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getType(), equalTo("password"));
  }

  @Test
  public void itHadUUIDInTheView() {
    PasswordView actual = (PasswordView) PasswordView.fromEntity(entity);

    assertThat(actual.getUuid(), equalTo(uuid.toString()));
  }
}
