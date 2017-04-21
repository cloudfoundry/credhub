package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.request.CertificateSetRequestFields;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateCredentialTest {

  private CertificateCredential subject;
  private CertificateCredentialData certificateCredentialData;

  private UUID canaryUuid;
  private Encryptor encryptor;

  private byte[] encryptedValue;
  private byte[] nonce;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);

      encryptedValue = "fake-encrypted-value".getBytes();
      nonce = "fake-nonce".getBytes();
      canaryUuid = UUID.randomUUID();

      final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
      when(encryptor.encrypt("my-priv"))
          .thenReturn(encryption);
      when(encryptor.decrypt(encryption)).thenReturn("my-priv");

      certificateCredentialData = new CertificateCredentialData("/Foo");
      subject = new CertificateCredential(certificateCredentialData)
          .setEncryptor(encryptor)
          .setCa("my-ca")
          .setCertificate("my-cert")
          .setPrivateKey("my-priv");
    });

    it("returns type certificate", () -> {
      assertThat(subject.getCredentialType(), equalTo("certificate"));
    });

    it("sets the nonce and the encrypted private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(certificateCredentialData.getEncryptedValue(), notNullValue());
      assertThat(certificateCredentialData.getNonce(), notNullValue());
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

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
        when(encryptor.encrypt("new private key"))
            .thenReturn(encryption);
        when(encryptor.decrypt(encryption))
            .thenReturn("new private key");
      });

      it("copies name and ca's name from existing", () -> {
        CertificateSetRequestFields fields = new CertificateSetRequestFields("new private key",
            "certificate", "ca");
        CertificateCredential newCredential = CertificateCredential
            .createNewVersion(subject, "anything I AM IGNORED", fields, encryptor,
                new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/Foo"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getCa(), equalTo("ca"));
        assertThat(newCredential.getCertificate(), equalTo("certificate"));
        assertThat(newCredential.getCaName(), equalTo(null));
      });

      it("creates new if no existing", () -> {
        CertificateSetRequestFields fields = new CertificateSetRequestFields("new private key",
            "certificate", "ca");
        CertificateCredential newCredential = CertificateCredential
            .createNewVersion(null, "/newName", fields, encryptor, new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
        assertThat(newCredential.getCa(), equalTo("ca"));
        assertThat(newCredential.getCertificate(), equalTo("certificate"));
        assertThat(newCredential.getCaName(), equalTo(null));
      });
    });
  }
}
