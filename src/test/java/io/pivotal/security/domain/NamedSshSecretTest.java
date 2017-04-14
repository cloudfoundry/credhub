package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class NamedSshSecretTest {

  private NamedSshSecret subject;

  private UUID encryptionKeyUuid;

  private Encryptor encryptor;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
      subject = new NamedSshSecret("/Foo");
    });

    it("returns type ssh", () -> {
      assertThat(subject.getSecretType(), equalTo("ssh"));
    });

    describe("#copyInto", () -> {

      beforeEach(() -> {
        byte[] encryptedValue = "fake-encrypted-value".getBytes();
        byte[] nonce = "fake-nonce".getBytes();
        UUID encryptionKeyUuid = UUID.randomUUID();
        when(encryptor.encrypt("test-private-key"))
            .thenReturn(new Encryption(encryptionKeyUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("test-private-key");
      });

      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        encryptionKeyUuid = UUID.randomUUID();

        NamedSshSecretData namedSshSecretData = new NamedSshSecretData("/foo");
        subject = new NamedSshSecret(namedSshSecretData);
        subject.setEncryptor(encryptor);
        subject.setPublicKey("fake-public-key");
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);
        subject.setPrivateKey("test-private-key");


        NamedSshSecret copy = new NamedSshSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/foo"));
        assertThat(copy.getPublicKey(), equalTo("fake-public-key"));
        assertThat(copy.getPrivateKey(), equalTo("test-private-key"));
        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));

        verify(encryptor).encrypt(any());
        verify(encryptor).decrypt(any(), any(), any());
      });
    });

    describe(".createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        when(encryptor.encrypt("new private key"))
            .thenReturn(new Encryption(encryptionKeyUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("new private key");

        NamedSshSecretData namedSshSecretData = new NamedSshSecretData("/existingName");
        namedSshSecretData.setEncryptedValue("old encrypted private key".getBytes());
        subject = new NamedSshSecret(namedSshSecretData);
        subject.setEncryptor(encryptor);
      });

      it("copies name from existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        NamedSshSecret newSecret = (NamedSshSecret) NamedSshSecret
            .createNewVersion(subject, "anything I AM IGNORED", fields, encryptor,
                new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getPrivateKey(), equalTo("new private key"));
        assertThat(newSecret.getPublicKey(), equalTo("public key"));
      });

      it("creates new if no existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        NamedSshSecret newSecret = (NamedSshSecret) NamedSshSecret
            .createNewVersion(null, "/newName", fields, encryptor, new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getPrivateKey(), equalTo("new private key"));
        assertThat(newSecret.getPublicKey(), equalTo("public key"));
      });
    });
  }
}
