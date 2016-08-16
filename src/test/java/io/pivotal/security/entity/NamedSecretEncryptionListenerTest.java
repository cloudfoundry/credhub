package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@ActiveProfiles({"dev", "FakeEncryptionService"})
public class NamedSecretEncryptionListenerTest {

  NamedSecretEncryptionListener subject;

  @Autowired
  EncryptionService encryptionService;

  NamedStringSecret namedStringSecret;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = NamedSecretEncryptionListener.class.newInstance();
    });

    describe("when a record is written", () -> {
      beforeEach(() -> {
        ((FakeEncryptionService) encryptionService).setCount(0);
        namedStringSecret = new NamedStringSecret("test").setValue("value");
      });

      it("it only encrypts the encryptedValue field when necessary", () -> {
        subject.encrypt(namedStringSecret);
        assertThat(namedStringSecret.getEncryptedValue(), notNullValue());
        assertThat(namedStringSecret.getNonce(), notNullValue());
        assertThat(((FakeEncryptionService) encryptionService).getCount(), equalTo(1));

        subject.encrypt(namedStringSecret);
        assertThat(((FakeEncryptionService) encryptionService).getCount(), equalTo(1));
      });
    });
  }
}