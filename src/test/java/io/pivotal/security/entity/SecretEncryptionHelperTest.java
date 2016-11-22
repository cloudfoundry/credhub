package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "FakeEncryptionService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretEncryptionHelperTest {

  @Autowired
  SecretEncryptionHelper subject;

  @Autowired
  EncryptionService encryptionService;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });


    describe("#refreshEncryptedValue", () -> {
      it("encrypts a private key and updates the EncryptedValueContainer", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");

        assertNotNull(valueContainer.getEncryptedValue());
        assertNotNull(valueContainer.getNonce());
      });

      it("only encrypts a given value one time", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");
        subject.refreshEncryptedValue(valueContainer, "some fake secret");

        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
      });

      it("does not error on null values", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
        subject.refreshEncryptedValue(valueContainer, null);
        assertThat(valueContainer.getNonce(), equalTo(null));
        assertThat(valueContainer.getEncryptedValue(), equalTo(null));
      });
    });

    describe("#retrieveClearTextValue", () -> {
      it("can get the clear text from a valueContainer", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");
        String clearTextValue = subject.retrieveClearTextValue(valueContainer);

        assertThat(clearTextValue, equalTo("some fake secret"));
      });
    });
  }
}
