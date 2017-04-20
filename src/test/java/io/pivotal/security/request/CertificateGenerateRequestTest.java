package io.pivotal.security.request;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.credential.Certificate;
import io.pivotal.security.service.GeneratorService;
import java.util.Arrays;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

@RunWith(Spectrum.class)
public class CertificateGenerateRequestTest {
  private GeneratorService generatorService;
  private CertificateGenerateRequest subject;
  private AccessControlEntry accessControlEntry;

  private CertificateGenerationParameters generationParameters;

  {
    describe("#generateSetRequest", () -> {
      beforeEach(() -> {
        generatorService = mock(GeneratorService.class);
        when(generatorService.generateCertificate(any(CertificateParameters.class)))
            .thenReturn(new Certificate("ca", "certificate", "private_key"));

        accessControlEntry = new AccessControlEntry("test-actor",
            Arrays.asList(READ, WRITE));

        subject = new CertificateGenerateRequest();
        subject.setType("certificate");
        subject.setName("test-name");
        generationParameters = new CertificateGenerationParameters();
        generationParameters.setCommonName("common-name");

        subject.setGenerationParameters(generationParameters);
        subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
        subject.setOverwrite(true);
      });

      it("creates set request and copies all fields from the generate request", () -> {
        BaseCredentialSetRequest setRequest = subject.generateSetRequest(generatorService);

        assertThat(setRequest.getType(), equalTo("certificate"));
        assertThat(setRequest.getName(), equalTo("test-name"));
        assertTrue(setRequest.isOverwrite());
        assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
        assertThat(((CertificateSetRequest) setRequest).getCertificateFields().getCa(), equalTo("ca"));
        assertThat(((CertificateSetRequest) setRequest).getCertificateFields().getCertificate(), equalTo("certificate"));
        assertThat(((CertificateSetRequest) setRequest).getCertificateFields().getPrivateKey(), equalTo("private_key"));

        ArgumentCaptor<CertificateParameters> captor = ArgumentCaptor.forClass(CertificateParameters.class);
        verify(generatorService).generateCertificate(captor.capture());

        assertThat(captor.getValue(), samePropertyValuesAs(new CertificateParameters(generationParameters)));
      });
    });
  }
}
