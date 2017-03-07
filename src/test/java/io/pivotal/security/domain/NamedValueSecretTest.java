package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

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
  private Encryptor encryptor;

  NamedValueSecret subject;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();
      when(encryptor.encrypt("my-value")).thenReturn(new Encryption(encryptedValue, nonce));
      when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("my-value");

      subject = new NamedValueSecret("Foo");
    });

    it("returns type value", () -> {
      assertThat(subject.getSecretType(), equalTo("value"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedValueSecret("foo").setEncryptor(encryptor);
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setValue("my-value");
        assertThat(subject.getEncryptedValue(), notNullValue());
        assertThat(subject.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue("my-value");
        assertThat(subject.getValue(), equalTo("my-value"));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setValue(null);
      });
    });

    describe(".createNewVersion and #createNewVersion", () -> {
      beforeEach(() -> {
        subject = new NamedValueSecret("/existingName");

        byte[] encryptedValue = "new-encrypted-value".getBytes();
        byte[] nonce = "new-nonce".getBytes();
        when(encryptor.encrypt("new value")).thenReturn(new Encryption(encryptedValue, nonce));
        when(encryptor.decrypt(any(UUID.class), eq(encryptedValue), eq(nonce))).thenReturn("new value");

        subject.setEncryptor(encryptor);
      });

      it("copies only name from existing", () -> {
        NamedValueSecret newSecret = subject.createNewVersion("new value");

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getValue(), equalTo("new value"));
      });

      describe("static overload", () -> {
        it("copies values from existing", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            subject,
            "/existingName",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/existingName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });

        it("copies the name from the existing version", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            subject,
            "IAMIGNOREDBECAUSEEXISTINGNAMEISUSED",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/existingName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });

        it("creates new if no existing", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            null,
            "/newName",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/newName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });
      });
    });

  }
}
