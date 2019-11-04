package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.UUID;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SshViewTest {
  private static final String CREDENTIAL_NAME = "/foo";
  private static final UUID CREDENTIAL_UUID = java.util.UUID.randomUUID();

  private SshCredentialVersion entity;

  @Before
  public void beforeEach() {
    final Encryptor encryptor = mock(Encryptor.class);
    final EncryptedValue encryption = new EncryptedValue(UUID.randomUUID(), "encrypted".getBytes(UTF_8), "nonce".getBytes(UTF_8));
    when(encryptor.encrypt(TestConstants.PRIVATE_KEY_4096)).thenReturn(
      encryption);
    when(encryptor.decrypt(encryption))
      .thenReturn(TestConstants.PRIVATE_KEY_4096);

    entity = new SshCredentialVersion(CREDENTIAL_NAME);
    entity.setEncryptor(encryptor);
    entity.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);
    entity.setPrivateKey(TestConstants.PRIVATE_KEY_4096);
    entity.setUuid(CREDENTIAL_UUID);
  }

  @Test
  public void createsAViewFromEntity() throws Exception {
    final CredentialView subject = SshView.fromEntity(entity);

    final String escapedPrivateKey = TestConstants.PRIVATE_KEY_4096.replaceAll("\\\\n", "\\n");
    System.out.println(escapedPrivateKey);
    final String expected = "{"
      + "\"type\":\"ssh\","
      + "\"version_created_at\":null,"
      + "\"id\":\"" + CREDENTIAL_UUID.toString() + "\","
      + "\"name\":\"/foo\","
      + "\"value\":{"
      + "\"public_key\":\"" + TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT + "\","
      + "\"private_key\":\"" + escapedPrivateKey + "\","
      + "\"public_key_fingerprint\":\"UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc\""
      + "}"
      + "}";

    final String json = JsonTestHelper.serializeToString(subject);
    assertThat(json.replaceAll("\\\\n", "\n"), equalTo(expected));
  }

  @Test
  public void setsUpdatedAtTimeOnGeneratedView() {
    final Instant now = Instant.now();
    entity.setVersionCreatedAt(now);
    final SshView subject = (SshView) SshView.fromEntity(entity);
    assertThat(subject.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void setsUuidOnGeneratedView() {
    final SshView subject = (SshView) SshView.fromEntity(entity);
    assertThat(subject.getUuid(), equalTo(CREDENTIAL_UUID.toString()));
  }
}
