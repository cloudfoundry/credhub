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
import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.service.GeneratorService;
import java.util.Arrays;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

@RunWith(Spectrum.class)
public class PasswordGenerateRequestTest {
  private GeneratorService generatorService;
  private PasswordGenerateRequest subject;
  private AccessControlEntry accessControlEntry;

  private StringGenerationParameters generationParameters;

  {
    describe("#generateSetRequest", () -> {
      beforeEach(() -> {
        generatorService = mock(GeneratorService.class);
        when(generatorService.generatePassword(any(StringGenerationParameters.class)))
            .thenReturn(new StringCredential("fake-password"));
        accessControlEntry = new AccessControlEntry("test-actor",
            Arrays.asList(READ, WRITE));
        subject = new PasswordGenerateRequest();
        subject.setType("password");
        subject.setName("test-name");
        generationParameters = new StringGenerationParameters().setExcludeNumber(true);
        subject.setGenerationParameters(generationParameters);
        subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
        subject.setOverwrite(true);
      });

      it("creates set request and copies all fields from the generate request", () -> {
        BaseCredentialSetRequest setRequest = subject.generateSetRequest(generatorService);

        assertThat(setRequest.getType(), equalTo("password"));
        assertThat(setRequest.getName(), equalTo("test-name"));
        assertTrue(setRequest.isOverwrite());
        assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
        assertThat(((PasswordSetRequest) setRequest).getPassword().getStringCredential(),
            equalTo("fake-password"));
        ArgumentCaptor<StringGenerationParameters> captor = ArgumentCaptor.forClass(StringGenerationParameters.class);
        verify(generatorService).generatePassword(captor.capture());

        assertThat(captor.getValue(), samePropertyValuesAs(generationParameters));
      });
    });
  }
}
