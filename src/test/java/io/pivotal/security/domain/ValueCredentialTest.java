package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.ValueCredentialData;
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
  }
}
