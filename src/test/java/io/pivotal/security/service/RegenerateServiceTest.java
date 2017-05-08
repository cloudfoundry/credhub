package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.CredentialView;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class RegenerateServiceTest {

  private CredentialDataService credentialDataService;
  private RegenerateService subject;

  private PasswordCredential passwordCredential;
  private SshCredential sshCredential;
  private RsaCredential rsaCredential;
  private JsonCredential credentialOfUnsupportedType;
  private StringGenerationParameters expectedParameters;
  private List<EventAuditRecordParameters> parametersList;
  private CredentialService credentialService;
  private AccessControlEntry currentUser;

  private GeneratorService generatorService;

  public UserContext userContext;

  {
    beforeEach(() -> {
      credentialDataService = mock(CredentialDataService.class);
      passwordCredential = mock(PasswordCredential.class);
      sshCredential = mock(SshCredential.class);
      rsaCredential = mock(RsaCredential.class);
      parametersList = newArrayList();
      credentialService = mock(CredentialService.class);
      generatorService = mock(GeneratorService.class);
      userContext = mock(UserContext.class);
      currentUser = mock(AccessControlEntry.class);

      when(credentialDataService.findMostRecent(eq("unsupported")))
          .thenReturn(credentialOfUnsupportedType);
      when(credentialService
          .save(
              eq(userContext),
              eq(parametersList),
              eq("password"),
              eq(true),
              anyString(),
              isA(StringGenerationParameters.class),
              isA(CredentialValue.class),
              anyList(),
              any(AccessControlEntry.class)))
          .thenReturn(mock(CredentialView.class));
      credentialOfUnsupportedType = new JsonCredential();
      subject = new RegenerateService(credentialDataService, credentialService,
          generatorService);
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
          when(generatorService.generatePassword(eq(expectedParameters)))
              .thenReturn(mock(StringCredentialValue.class));

          subject
              .performRegenerate(userContext,
                  parametersList,
                  passwordGenerateRequest, 
                  currentUser);
        });

        describe("when regenerating password", () -> {
          it("should generate a new password", () -> {

            verify(credentialService)
                .save(
                    eq(userContext),
                    eq(parametersList),
                    eq("password"),
                    eq(true),
                    eq("password"),
                    isA(StringGenerationParameters.class),
                    isA(StringCredentialValue .class),
                    eq(Collections.emptyList()),
                    eq(currentUser));
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
                    .performRegenerate(userContext, parametersList, passwordGenerateRequest, currentUser);
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
            when(generatorService.generateSshKeys(any(SshGenerationParameters.class)))
                .thenReturn(mock(SshCredentialValue.class));

            subject
                .performRegenerate(userContext, parametersList, sshRegenerateRequest, currentUser);
          });

          it("should generate a new ssh key pair", () -> {
            verify(credentialService)
                .save(
                    eq(userContext),
                    eq(parametersList),
                    eq("ssh"),
                    eq(true),
                    eq("ssh"),
                    eq(null),
                    isA(SshCredentialValue.class),
                    eq(Collections.emptyList()),
                    eq(currentUser));
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
            when(generatorService.generateRsaKeys(any(RsaGenerationParameters.class)))
                .thenReturn(mock(RsaCredentialValue.class));

            subject
                .performRegenerate(userContext, parametersList, rsaRegenerateRequest, currentUser);
          });

          it("should generate a new rsa key pair", () -> {
            verify(credentialService)
                .save(
                eq(userContext),
                eq(parametersList),
                eq("rsa"),
                eq(true),
                eq("rsa"),
                eq(null),
                isA(RsaCredentialValue.class),
                eq(Collections.emptyList()),
                eq(currentUser));
          });
        });
      });

      describe("when regenerating a credential that does not exist", () -> {
        itThrows("an exception", EntryNotFoundException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
              .setName("missing_entry");

          subject.performRegenerate(userContext, parametersList, passwordGenerateRequest, currentUser);
        });
      });

      describe("when attempting regenerate of non-regeneratable type", () -> {
        itThrows("an exception", ParameterizedValidationException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest()
              .setName("unsupported");

          subject.performRegenerate(userContext, parametersList, passwordGenerateRequest, currentUser);
        });
      });
    });
  }
}
