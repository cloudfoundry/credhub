package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CanaryDataService;
import io.pivotal.security.entity.NamedCanary;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionProviderCanary.CANARY_NAME;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EncryptionProviderCanaryTest {

  @MockBean
  CanaryDataService canaryDataService;

  @SpyBean
  EncryptionService encryptionService;

  @Autowired
  EncryptionProviderCanary subject;

  @Autowired
  EncryptionConfiguration encryptionConfiguration;

  {
    wireAndUnwire(this, false);

    describe("#checkForDataCorruption", () -> {
      describe("when there is no existing canary", () -> {
        beforeEach(() -> {
          when(canaryDataService.find(CANARY_NAME)).thenReturn(null);
        });

        it("should create a new canary", () -> {
          String expectedCanaryValue = new String(new byte[256], "UTF-8");
          EncryptionService.Encryption encryptedValue = new EncryptionService.Encryption("test-nonce".getBytes(), "test-encrypted-value".getBytes());
          doReturn(encryptedValue).when(encryptionService).encrypt(expectedCanaryValue);

          reset(canaryDataService);
          subject.checkForDataCorruption();

          ArgumentCaptor<NamedCanary> argumentCaptor = ArgumentCaptor.forClass(NamedCanary.class);
          verify(canaryDataService, times(1)).save(argumentCaptor.capture());

          NamedCanary canary = argumentCaptor.getValue();

          assertThat(canary.getNonce(), equalTo("test-nonce".getBytes()));
          assertThat(canary.getEncryptedValue(), equalTo("test-encrypted-value".getBytes()));
        });

        itThrows("an error if it can't encrypt the canary", RuntimeException.class, () -> {
          doThrow(Exception.class).when(encryptionService).encrypt(any(String.class));

          subject.checkForDataCorruption();
        });
      });

      describe("when there is an existing canary", () -> {
        beforeEach(() -> {
          NamedCanary canary = new NamedCanary();
          canary.setNonce("test-nonce".getBytes());
          canary.setEncryptedValue("fake-encrypted-value".getBytes());

          when(canaryDataService.find(CANARY_NAME)).thenReturn(canary);
        });

        it("should not fail if the decrypted value matches the expected value", () -> {
          String canaryValue = new String(new byte[256], "UTF-8");
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
