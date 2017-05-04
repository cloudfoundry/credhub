package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.CredentialView;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class RegenerateServiceTest {

  private CredentialDataService credentialDataService;
  private GenerateService generateService;
  private RegenerateService subject;

  private PasswordCredential passwordCredential;
  private SshCredential sshCredential;
  private RsaCredential rsaCredential;
  private JsonCredential credentialOfUnsupportedType;
  private StringGenerationParameters expectedParameters;
  private List<EventAuditRecordParameters> parametersList;

  {
    beforeEach(() -> {
      credentialDataService = mock(CredentialDataService.class);
      generateService = mock(GenerateService.class);
      passwordCredential = mock(PasswordCredential.class);
      sshCredential = mock(SshCredential.class);
      rsaCredential = mock(RsaCredential.class);
      parametersList = newArrayList();

      when(credentialDataService.findMostRecent(eq("unsupported")))
          .thenReturn(credentialOfUnsupportedType);
      when(generateService
          .performGenerate(
              isA(UserContext.class),
              any(),
              isA(BaseCredentialGenerateRequest.class),
              isA(AccessControlEntry.class)))
          .thenReturn(mock(CredentialView.class));
      credentialOfUnsupportedType = new JsonCredential();
      subject = new RegenerateService(credentialDataService, generateService);
    });

    describe("#performRegenerate", () -> {
      describe("password", () -> {
        beforeEach(() -> {
          when(credentialDataService.findMostRecent(eq("password")))
              .thenReturn(passwordCredential);
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
              .setName("password");
          expectedParameters = new StringGenerationParameters()
              .setExcludeLower(true)
              .setExcludeUpper(true)
              .setLength(20);
          when(passwordCredential.getName()).thenReturn("password");
          when(passwordCredential.getCredentialType()).thenReturn("password");
          when(passwordCredential.getGenerationParameters())
              .thenReturn(expectedParameters);

          subject
              .performRegenerate(mock(UserContext.class), parametersList, passwordGenerateRequest, mock(AccessControlEntry.class));
        });

        describe("when regenerating password", () -> {
          it("should generate a new password", () -> {
            ArgumentCaptor<BaseCredentialGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseCredentialGenerateRequest.class);

            verify(generateService)
                .performGenerate(
                    isA(UserContext.class),
                    any(),
                    generateRequestCaptor.capture(),
                    isA(AccessControlEntry.class));

            PasswordGenerateRequest generateRequest = (PasswordGenerateRequest) generateRequestCaptor
                .getValue();

            assertThat(generateRequest.getName(), equalTo("password"));
            assertThat(generateRequest.getType(), equalTo("password"));
            assertThat(generateRequest.getGenerationParameters(),
                samePropertyValuesAs(expectedParameters));
          });

        });

        describe("when regenerating password not generated by us", () -> {
          beforeEach(() -> {
            when(passwordCredential.getGenerationParameters())
                .thenReturn(null);
          });

          itThrowsWithMessage(
              "it returns an error",
              ParameterizedValidationException.class,
              "error.cannot_regenerate_non_generated_password",
              () -> {
                CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
                    .setName("password");

                subject
                    .performRegenerate(mock(UserContext.class), parametersList, passwordGenerateRequest, mock(AccessControlEntry.class));
              });
        });
      });

      describe("ssh & rsa", () -> {
        describe("when regenerating ssh", () -> {
          beforeEach(() -> {
            when(credentialDataService.findMostRecent(eq("ssh")))
                .thenReturn(sshCredential);
            CredentialRegenerateRequest sshRegenerateRequest = new CredentialRegenerateRequest()
                .setName("ssh");
            when(sshCredential.getName()).thenReturn("ssh");
            when(sshCredential.getCredentialType()).thenReturn("ssh");

            subject
                .performRegenerate(mock(UserContext.class), parametersList, sshRegenerateRequest, mock(AccessControlEntry.class));
          });

          it("should generate a new ssh key pair", () -> {
            ArgumentCaptor<BaseCredentialGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseCredentialGenerateRequest.class);

            verify(generateService)
                .performGenerate(
                    isA(UserContext.class),
                    eq(parametersList),
                    generateRequestCaptor.capture(),
                    isA(AccessControlEntry.class));

            SshGenerateRequest generateRequest = (SshGenerateRequest) generateRequestCaptor
                .getValue();

            assertThat(generateRequest.getName(), equalTo("ssh"));
            assertThat(generateRequest.getType(), equalTo("ssh"));
          });
        });

        describe("when regenerating rsa", () -> {
          beforeEach(() -> {
            when(credentialDataService.findMostRecent(eq("rsa")))
                .thenReturn(rsaCredential);
            CredentialRegenerateRequest rsaRegenerateRequest = new CredentialRegenerateRequest()
                .setName("rsa");
            when(rsaCredential.getName()).thenReturn("rsa");
            when(rsaCredential.getCredentialType()).thenReturn("rsa");

            subject
                .performRegenerate(mock(UserContext.class), parametersList, rsaRegenerateRequest, mock(AccessControlEntry.class));
          });

          it("should generate a new rsa key pair", () -> {
            ArgumentCaptor<BaseCredentialGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseCredentialGenerateRequest.class);

            verify(generateService)
                .performGenerate(
                    isA(UserContext.class),
                    eq(parametersList),
                    generateRequestCaptor.capture(),
                    isA(AccessControlEntry.class));

            RsaGenerateRequest generateRequest = (RsaGenerateRequest) generateRequestCaptor
                .getValue();

            assertThat(generateRequest.getName(), equalTo("rsa"));
            assertThat(generateRequest.getType(), equalTo("rsa"));
          });
        });
      });

      describe("when regenerating a credential that does not exist", () -> {
        itThrows("an exception", EntryNotFoundException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
              .setName("missing_entry");

          subject.performRegenerate(mock(UserContext.class), parametersList, passwordGenerateRequest, mock(AccessControlEntry.class));
        });
      });

      describe("when attempting regenerate of non-regeneratable type", () -> {
        itThrows("an exception", ParameterizedValidationException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
              .setName("unsupported");

          subject.performRegenerate(mock(UserContext.class), parametersList, passwordGenerateRequest, mock(AccessControlEntry.class));
        });
      });
    });
  }
}
