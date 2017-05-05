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
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.service.GeneratorService;
import java.util.Arrays;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

@RunWith(Spectrum.class)
public class SshGenerateRequestTest {
  private GeneratorService generatorService;
  private SshGenerateRequest subject;
  private AccessControlEntry accessControlEntry;

  private SshGenerationParameters generationParameters;

  {
    describe("#generateSetRequest", () -> {
      beforeEach(() -> {
        generatorService = mock(GeneratorService.class);
        when(generatorService.generateSshKeys(any(SshGenerationParameters.class)))
            .thenReturn(new SshCredentialValue("pub","priv", "fingerprint"));

        accessControlEntry = new AccessControlEntry("test-actor",
            Arrays.asList(READ, WRITE));

        subject = new SshGenerateRequest();
        subject.setType("ssh");
        subject.setName("test-name");
        generationParameters = new SshGenerationParameters();
        generationParameters.setKeyLength(4096);

        subject.setGenerationParameters(generationParameters);
        subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
        subject.setOverwrite(true);
      });

      it("creates set request and copies all fields from the generate request", () -> {
        BaseCredentialSetRequest setRequest = subject.generateSetRequest(generatorService);

        assertThat(setRequest.getType(), equalTo("ssh"));
        assertThat(setRequest.getName(), equalTo("test-name"));
        assertTrue(setRequest.isOverwrite());
        assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
        assertThat(((SshSetRequest) setRequest).getSshKeyValue().getPublicKey(), equalTo("pub"));
        assertThat(((SshSetRequest) setRequest).getSshKeyValue().getPrivateKey(), equalTo("priv"));

        ArgumentCaptor<SshGenerationParameters> captor = ArgumentCaptor.forClass(SshGenerationParameters.class);
        verify(generatorService).generateSshKeys(captor.capture());

        assertThat(captor.getValue(), samePropertyValuesAs(generationParameters));
      });
    });
  }
}
