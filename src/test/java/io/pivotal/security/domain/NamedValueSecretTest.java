package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedValueSecretData;
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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class NamedValueSecretTest {

  NamedValueSecret subject;
  private Encryptor encryptor;
  private UUID canaryUuid;
  private NamedValueSecretData namedValueSecretData;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();
      when(encryptor.encrypt("my-value"))
          .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
          .thenReturn("my-value");

      subject = new NamedValueSecret("Foo");
    });

    it("returns type value", () -> {
      assertThat(subject.getSecretType(), equalTo("value"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        namedValueSecretData = new NamedValueSecretData("foo");
        subject = new NamedValueSecret(namedValueSecretData).setEncryptor(encryptor);
      });

      it("encrypts the value", () -> {
        subject.setValue("my-value");
        assertThat(namedValueSecretData.getEncryptedValue(), notNullValue());
        assertThat(namedValueSecretData.getNonce(), notNullValue());
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
        when(encryptor.encrypt("new value"))
            .thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce)))
            .thenReturn("new value");

        subject = new NamedValueSecret("/existingName");
        subject.setEncryptor(encryptor);
        namedValueSecretData.setEncryptedValue("old encrypted value".getBytes());
      });

      it("copies values from existing, except value", () -> {
        NamedValueSecret newSecret = NamedValueSecret
            .createNewVersion(subject, "anything I AM IGNORED", "new value", encryptor,
                new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getValue(), equalTo("new value"));
      });

      it("creates new if no existing", () -> {
        NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            null,
            "/newName",
            "new value",
            encryptor, new ArrayList<>());

        assertThat(newSecret.getName(), equalTo("/newName"));
        assertThat(newSecret.getValue(), equalTo("new value"));
      });
    });
  }
}
