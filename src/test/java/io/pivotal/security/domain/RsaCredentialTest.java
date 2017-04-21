package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.request.KeySetRequestFields;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class RsaCredentialTest {

  private RsaCredential subject;
  private Encryptor encryptor;
  private UUID canaryUuid;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      subject = new RsaCredential("/Foo");
    });

    it("returns type rsa", () -> {
      assertThat(subject.getCredentialType(), equalTo("rsa"));
    });

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
        when(encryptor.encrypt("new private key"))
            .thenReturn(encryption);
        when(encryptor.decrypt(encryption))
            .thenReturn("new private key");

        RsaCredentialData delegate = new RsaCredentialData("/existingName");
        delegate.setEncryptedValue("old encrypted private key".getBytes());
        subject = new RsaCredential(delegate);
        subject.setEncryptor(encryptor);
      });

      it("copies name from existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        RsaCredential newCredential = RsaCredential
            .createNewVersion(subject, "anything I AM IGNORED", fields, encryptor,
                new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/existingName"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getPublicKey(), equalTo("public key"));
      });

      it("creates new if no existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        RsaCredential newCredential = RsaCredential
            .createNewVersion(null, "/newName", fields, encryptor, new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getPublicKey(), equalTo("public key"));
      });
    });
  }
}
