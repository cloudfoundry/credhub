package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedRsaSecretData;
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
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class NamedRsaSecretTest {

  private NamedRsaSecret subject;

  private Encryptor encryptor;

  private byte[] encryptedPrivateKey;
  private byte[] privateKeyNonce;
  private UUID canaryUuid;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      subject = new NamedRsaSecret("/Foo");
    });

    it("returns type rsa", () -> {
      assertThat(subject.getSecretType(), equalTo("rsa"));
    });

    describe("#copyInto", () -> {
      beforeEach(() -> {
        canaryUuid = UUID.randomUUID();
        encryptedPrivateKey = "encrypted-fake-private-key".getBytes();
        privateKeyNonce = "some nonce".getBytes();
        when(encryptor.encrypt(eq("fake-private-key"))).thenReturn(new Encryption(
            canaryUuid,
            encryptedPrivateKey,
            privateKeyNonce
        ));
        when(encryptor.decrypt(any(), any(), any())).thenReturn(
            "fake-private-key"
        );
      });

      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();
        NamedRsaSecretData delegate = new NamedRsaSecretData("/foo");

        delegate.setPublicKey("fake-public-key");
        delegate.setEncryptedValue(encryptedPrivateKey);
        delegate.setNonce(privateKeyNonce);
        delegate.setUuid(canaryUuid);
        delegate.setVersionCreatedAt(frozenTime);
        delegate.setEncryptionKeyUuid(encryptionKeyUuid);
        subject = new NamedRsaSecret(delegate);
        subject.setEncryptor(encryptor);

        NamedRsaSecret copy = new NamedRsaSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/foo"));
        assertThat(copy.getPublicKey(), equalTo("fake-public-key"));
        assertThat(copy.getPrivateKey(), equalTo("fake-private-key"));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });

    describe(".createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        when(encryptor.encrypt("new private key"))
            .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("new private key");

        NamedRsaSecretData delegate = new NamedRsaSecretData("/existingName");
        delegate.setEncryptedValue("old encrypted private key".getBytes());
        subject = new NamedRsaSecret(delegate);
        subject.setEncryptor(encryptor);
      });

      it("copies name from existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        NamedRsaSecret newSecret = (NamedRsaSecret) NamedRsaSecret
            .createNewVersion(subject, "anything I AM IGNORED", fields, encryptor,
                new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getPrivateKey(), equalTo("new private key"));
        assertThat(newSecret.getPublicKey(), equalTo("public key"));
      });

      it("creates new if no existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        NamedRsaSecret newSecret = (NamedRsaSecret) NamedRsaSecret
            .createNewVersion(null, "/newName", fields, encryptor, new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getPrivateKey(), equalTo("new private key"));
        assertThat(newSecret.getPublicKey(), equalTo("public key"));
      });
    });
  }
}
