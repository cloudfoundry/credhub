package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class ValueCredentialTest {

  ValueCredential subject;
  private Encryptor encryptor;
  private UUID canaryUuid;
  private ValueCredentialData valueCredentialData;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();
      final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
      when(encryptor.encrypt("my-value"))
          .thenReturn(encryption);
      when(encryptor.decrypt(encryption))
          .thenReturn("my-value");

      subject = new ValueCredential("Foo");
    });

    it("returns type value", () -> {
      assertThat(subject.getCredentialType(), equalTo("value"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        valueCredentialData = new ValueCredentialData("foo");
        subject = new ValueCredential(valueCredentialData).setEncryptor(encryptor);
      });

      it("encrypts the value", () -> {
        subject.setValue("my-value");
        assertThat(valueCredentialData.getEncryptedValue(), notNullValue());
        assertThat(valueCredentialData.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue("my-value");
        assertThat(subject.getValue(), equalTo("my-value"));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setValue(null);
      });
    });

    describe("#createNewVersion", () -> {
      beforeEach(() -> {
        byte[] encryptedValue = "new-fake-encrypted".getBytes();
        byte[] nonce = "new-fake-nonce".getBytes();
        final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
        when(encryptor.encrypt("new value"))
            .thenReturn(encryption);
        when(encryptor.decrypt(encryption))
            .thenReturn("new value");

        subject = new ValueCredential("/existingName");
        subject.setEncryptor(encryptor);
        valueCredentialData.setEncryptedValue("old encrypted value".getBytes());
      });

      it("copies values from existing, except value", () -> {
        ValueCredential newCredential = ValueCredential
            .createNewVersion(subject, "anything I AM IGNORED", "new value", encryptor,
                new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/existingName"));
        assertThat(newCredential.getValue(), equalTo("new value"));
      });

      it("creates new if no existing", () -> {
        ValueCredential newCredential = ValueCredential.createNewVersion(
            null,
            "/newName",
            "new value",
            encryptor, new ArrayList<>());

        assertThat(newCredential.getName(), equalTo("/newName"));
        assertThat(newCredential.getValue(), equalTo("new value"));
      });
    });
  }
}
