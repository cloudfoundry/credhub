package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.SshCredentialData;
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
public class SshCredentialTest {

  private SshCredential subject;
  private Encryptor encryptor;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
      subject = new SshCredential("/Foo");
    });

    it("returns type ssh", () -> {
      assertThat(subject.getCredentialType(), equalTo("ssh"));
    });

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        final Encryption encryption = new Encryption(UUID.randomUUID(), encryptedValue, nonce);
        when(encryptor.encrypt("new private key"))
            .thenReturn(encryption);
        when(encryptor.decrypt(encryption))
            .thenReturn("new private key");

        SshCredentialData sshCredentialData = new SshCredentialData("/existingName");
        sshCredentialData.setEncryptedValue("old encrypted private key".getBytes());
        subject = new SshCredential(sshCredentialData);
        subject.setEncryptor(encryptor);
      });

      it("copies name from existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        SshCredential newCredential = SshCredential
            .createNewVersion(subject, "anything I AM IGNORED", fields, encryptor,
                new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/existingName"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getPublicKey(), equalTo("public key"));
      });

      it("creates new if no existing", () -> {
        KeySetRequestFields fields = new KeySetRequestFields("new private key", "public key");
        SshCredential newCredential = SshCredential
            .createNewVersion(null, "/newName", fields, encryptor, new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getPublicKey(), equalTo("public key"));
      });
    });
  }
}
