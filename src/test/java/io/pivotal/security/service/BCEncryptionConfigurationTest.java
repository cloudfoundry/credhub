package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.config.DevKeyProvider;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.util.ReflectionTestUtils;

import javax.xml.bind.DatatypeConverter;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "BCEncryptionConfigurationTest"})
public class BCEncryptionConfigurationTest {
  @Autowired
  private BCEncryptionConfiguration subject;

  {
    wireAndUnwire(this);

    describe("getKey", () -> {
      it("should use the correct algorithm", () -> {
        assertThat(subject.getKey().getAlgorithm(), equalTo("AES"));
      });

      it("should use key of length 128 bits", () -> {
        assertThat(subject.getKey().getEncoded().length, equalTo(16));
      });

      it("should create a key using the provided dev key value", () -> {
        // this line is needed to ensure that a new key will be initialized
        ReflectionTestUtils.setField(subject, "key", null);
        subject.devKeyProvider = Mockito.mock(DevKeyProvider.class);
        when(subject.devKeyProvider.getDevKey()).thenReturn("0123456789ABCDEF0123456789ABCDEF");
        assertThat(DatatypeConverter.printHexBinary(subject.getKey().getEncoded()), equalTo("0123456789ABCDEF0123456789ABCDEF"));
      });
    });
  }
}
