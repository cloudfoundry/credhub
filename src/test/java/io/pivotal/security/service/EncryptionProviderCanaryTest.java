package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.CanaryDataService;
import io.pivotal.security.entity.NamedCanary;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionProviderCanary.CANARY_NAME;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class EncryptionProviderCanaryTest {

  @Mock
  CanaryDataService canaryDataService;

  @Spy
  @Autowired
  EncryptionService encryptionService;

  @Autowired
  @InjectMocks
  EncryptionProviderCanary subject;

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  {
    wireAndUnwire(this);

    describe("#checkForDataCorruption", () -> {
      describe("when there is no existing canary", () -> {
        beforeEach(() -> {
          when(canaryDataService.findOneByName(CANARY_NAME)).thenReturn(null);
        });

        it("should create a new canary", () -> {
          String expectedCanaryValue = new String(new byte[128], "UTF-8");
          EncryptionService.Encryption encryptedValue = new EncryptionService.Encryption("test-nonce".getBytes(), "test-encrypted-value".getBytes());
          doReturn(encryptedValue).when(encryptionService).encrypt(expectedCanaryValue);

          subject.checkForDataCorruption();

          ArgumentCaptor<NamedCanary> argumentCaptor = ArgumentCaptor.forClass(NamedCanary.class);
          verify(canaryDataService, times(1)).save(argumentCaptor.capture());

          NamedCanary canary = argumentCaptor.getValue();

          assertThat(canary.getNonce(), equalTo("test-nonce".getBytes()));
          assertThat(canary.getEncryptedValue(), equalTo("test-encrypted-value".getBytes()));
        });

        itThrowsWithMessage("raises an error if it can't save the canary", RuntimeException.class, "Failed to create encryption canary value.", () -> {
          doThrow(RuntimeException.class).when(encryptionService).encrypt(any(String.class));

          subject.checkForDataCorruption();
        });
      });

      describe("when there is an existing canary", () -> {
        beforeEach(() -> {
          NamedCanary canary = new NamedCanary();
          canary.setNonce("test-nonce".getBytes());
          canary.setEncryptedValue("fake-encrypted-value".getBytes());

          when(canaryDataService.findOneByName(CANARY_NAME)).thenReturn(canary);
        });

        it("should not fail if the decrypted value matches the expected value", () -> {
          String canaryValue = new String(new byte[128], "UTF-8");
          doReturn(canaryValue).when(encryptionService).decrypt("test-nonce".getBytes(), "fake-encrypted-value".getBytes());

          subject.checkForDataCorruption();

          // pass
        });

        itThrowsWithMessage("raises an error if the decrypted canary value does not match the excepted value", RuntimeException.class, "Canary value is incorrect. Database has been tampered with.", () -> {
          String canaryValue = "TAMPERED";
          doReturn(canaryValue).when(encryptionService).decrypt("test-nonce".getBytes(), "fake-encrypted-value".getBytes());

          subject.checkForDataCorruption();
        });
      });
    });
  }
}
