package io.pivotal.security.view;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.helper.JsonTestHelper;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.TestConstants;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SshViewTest {
  private static final String CREDENTIAL_NAME = "/foo";
  private static final UUID CREDENTIAL_UUID = java.util.UUID.randomUUID();

  private SshCredential entity;

  @Before
  public void beforeEach() {
    Encryptor encryptor = mock(Encryptor.class);
    final Encryption encryption = new Encryption(UUID.randomUUID(), "encrypted".getBytes(), "nonce".getBytes());
    when(encryptor.encrypt(TestConstants.PRIVATE_KEY_4096)).thenReturn(
        encryption);
    when(encryptor.decrypt(encryption))
        .thenReturn(TestConstants.PRIVATE_KEY_4096);
    entity = new SshCredential(CREDENTIAL_NAME)
        .setEncryptor(encryptor)
        .setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT)
        .setPrivateKey(TestConstants.PRIVATE_KEY_4096);
    entity.setUuid(CREDENTIAL_UUID);
  }

  @Test
  public void createsAViewFromEntity() {
    final CredentialView subject = SshView.fromEntity(entity);

    JSONObject obj = new JSONObject();
    obj.put("public_key", TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);
    obj.put("private_key", TestConstants.PRIVATE_KEY_4096);
    obj.put("public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc");
    String expected = "{"
        + "\"type\":\"ssh\","
        + "\"version_created_at\":null,"
        + "\"id\":\"" + CREDENTIAL_UUID.toString() + "\","
        + "\"name\":\"/foo\","
        + "\"value\":" + obj.toString() + "}";
    String json = JsonTestHelper.serializeToString(subject);
    assertThat(json, equalTo(expected));
  }

  @Test
  public void setsUpdatedAtTimeOnGeneratedView() {
    Instant now = Instant.now();
    entity.setVersionCreatedAt(now);
    final SshView subject = (SshView) SshView.fromEntity(entity);
    assertThat(subject.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void setsUuidOnGeneratedView() {
    SshView subject = (SshView) SshView.fromEntity(entity);
    assertThat(subject.getUuid(), equalTo(CREDENTIAL_UUID.toString()));
  }
}
