package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedCertificateSecretTest {
  private NamedCertificateSecret subject;

  private Encryptor encryptor;

  private byte[] encryptedValue;

  private byte[] nonce;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
      encryptedValue = "fake-encrypted-value".getBytes();
      nonce = "fake-nonce".getBytes();
      when(encryptor.encrypt("my-priv")).thenReturn(new Encryption(encryptedValue, nonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("my-priv");

      subject = new NamedCertificateSecret("/Foo")
          .setEncryptor(encryptor)
          .setCa("my-ca")
          .setCertificate("my-cert")
          .setPrivateKey("my-priv");
    });

    it("returns type certificate", () -> {
      assertThat(subject.getSecretType(), equalTo("certificate"));
    });

    it("sets the nonce and the encrypted private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getEncryptedValue(), notNullValue());
      assertThat(subject.getNonce(), notNullValue());
    });

    it("can decrypt the private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getPrivateKey(), equalTo("my-priv"));
    });

    it("adds a slash to caName", () -> {
      subject.setCaName("something");
      assertThat(subject.getCaName(), equalTo("/something"));

      subject.setCaName("/something");
      assertThat(subject.getCaName(), equalTo("/something"));

      subject.setCaName("");
      assertThat(subject.getCaName(), equalTo(""));

      subject.setCaName(null);
      assertThat(subject.getCaName(), equalTo(null));
    });

    describe("#copyInto", () -> {
      it("should copy the correct values", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();

        subject = new NamedCertificateSecret("/name");
        subject.setCa("fake-ca");
        subject.setCertificate("fake-certificate");
        subject.setEncryptedValue("fake-private-key".getBytes());
        subject.setNonce("fake-nonce".getBytes());
        subject.setCaName("ca-name");
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);

        NamedCertificateSecret copy = new NamedCertificateSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/name"));
        assertThat(copy.getCaName(), equalTo("/ca-name"));
        assertThat(copy.getCa(), equalTo("fake-ca"));
        assertThat(copy.getEncryptedValue(), equalTo("fake-private-key".getBytes()));
        assertThat(copy.getNonce(), equalTo("fake-nonce".getBytes()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
