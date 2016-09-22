package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.config.DevKeyProvider;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.when;

import javax.xml.bind.DatatypeConverter;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "BCEncryptionConfigurationTest"})
public class BCEncryptionConfigurationTest {
  @Autowired
  private BCEncryptionConfiguration subject;

  @Mock
  DevKeyProvider devKeyProvider;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(devKeyProvider.getDevKey()).thenReturn("0123456789ABCDEF0123456789ABCDEF");
      subject.devKeyProvider = devKeyProvider;
      subject.init();
    });

    describe("getKey", () -> {
      it("should use the correct algorithm", () -> {
        assertThat(subject.getKey().getAlgorithm(), equalTo("AES"));
      });

      it("should create a key using the dev key", () -> {
        assertThat(DatatypeConverter.printHexBinary(subject.getKey().getEncoded()), equalTo("0123456789ABCDEF0123456789ABCDEF"));
      });
    });
  }
}