package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.request.PermissionEntry;
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
  private UserCredential userCredential;
  private SshCredential sshCredential;
  private RsaCredential rsaCredential;
  private JsonCredential credentialOfUnsupportedType;
  private StringGenerationParameters expectedParameters;
  private List<EventAuditRecordParameters> auditRecordParameters;
  private CredentialService credentialService;
  private PermissionEntry currentUser;

  private GeneratorService generatorService;

  public UserContext userContext;

  {
    beforeEach(() -> {
      credentialDataService = mock(CredentialDataService.class);
      passwordCredential = mock(PasswordCredential.class);
      userCredential = mock(UserCredential.class);
      sshCredential = mock(SshCredential.class);
      rsaCredential = mock(RsaCredential.class);
      auditRecordParameters = newArrayList();
      credentialService = mock(CredentialService.class);
      generatorService = mock(GeneratorService.class);
      userContext = mock(UserContext.class);
      currentUser = mock(PermissionEntry.class);

      when(credentialDataService.findMostRecent(eq("unsupported")))
          .thenReturn(credentialOfUnsupportedType);
      when(credentialService
          .save(
              eq("password"),
              anyString(),
              isA(CredentialValue.class),
              isA(StringGenerationParameters.class),
              anyList(),
              eq(true),
              eq(userContext),
              any(PermissionEntry.class),
              eq(auditRecordParameters)
          ))
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
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
          passwordGenerateRequest.setName("password");
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
              .performRegenerate(passwordGenerateRequest.getName(), userContext,
                  currentUser, auditRecordParameters
              );
        });

        describe("when regenerating password", () -> {
          it("should generate a new password", () -> {

            verify(credentialService)
                .save(
                    eq("password"),
                    eq("password"),
                    isA(StringCredentialValue.class),
                    isA(StringGenerationParameters.class),
                    eq(Collections.emptyList()),
                    eq(true),
                    eq(userContext),
                    eq(currentUser),
                    eq(auditRecordParameters)
                );
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
                CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
                passwordGenerateRequest.setName("password");

                subject
                    .performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
              });
        });
      });

      describe("user", () -> {
        beforeEach(() -> {
          when(credentialDataService.findMostRecent(eq("user")))
              .thenReturn(userCredential);
          CredentialRegenerateRequest userGenerateRequest = new CredentialRegenerateRequest();
          userGenerateRequest.setName("user");
          expectedParameters = new StringGenerationParameters()
              .setExcludeLower(true)
              .setExcludeUpper(true)
              .setLength(20)
              .setUsername("Darth Vader");
          when(userCredential.getName()).thenReturn("user");
          when(userCredential.getCredentialType()).thenReturn("user");
          when(userCredential.getGenerationParameters())
              .thenReturn(expectedParameters);
          when(userCredential.getUsername()).thenReturn("Darth Vader");
          when(generatorService.generateUser(eq("Darth Vader"), eq(expectedParameters)))
              .thenReturn(mock(UserCredentialValue.class));

          subject
              .performRegenerate(userGenerateRequest.getName(), userContext,
                  currentUser, auditRecordParameters
              );
        });

        describe("when regenerating user", () -> {
          it("should generate a new password for the credential", () -> {

            verify(credentialService)
                .save(
                    eq("user"),
                    eq("user"),
                    isA(UserCredentialValue.class),
                    isA(StringGenerationParameters.class),
                    eq(Collections.emptyList()),
                    eq(true),
                    eq(userContext),
                    eq(currentUser),
                    eq(auditRecordParameters)
                );
          });
        });

        describe("when regenerating user not generated by us", () -> {
          beforeEach(() -> {
            when(userCredential.getGenerationParameters())
                .thenReturn(null);
          });

          itThrowsWithMessage(
              "it returns an error",
              ParameterizedValidationException.class,
              "error.cannot_regenerate_non_generated_user",
              () -> {
                CredentialRegenerateRequest userGenerateRequest = new CredentialRegenerateRequest();
                userGenerateRequest.setName("user");

                subject
                    .performRegenerate(userGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
              });
        });
      });

      describe("ssh & rsa", () -> {
        describe("when regenerating ssh", () -> {
          beforeEach(() -> {
            when(credentialDataService.findMostRecent(eq("ssh")))
                .thenReturn(sshCredential);
            CredentialRegenerateRequest sshRegenerateRequest = new CredentialRegenerateRequest();
            sshRegenerateRequest.setName("ssh");
            when(sshCredential.getName()).thenReturn("ssh");
            when(sshCredential.getCredentialType()).thenReturn("ssh");
            when(generatorService.generateSshKeys(any(SshGenerationParameters.class)))
                .thenReturn(mock(SshCredentialValue.class));

            subject
                .performRegenerate(sshRegenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
          });

          it("should generate a new ssh key pair", () -> {
            verify(credentialService)
                .save(
                    eq("ssh"),
                    eq("ssh"),
                    isA(SshCredentialValue.class),
                    eq(null),
                    eq(Collections.emptyList()),
                    eq(true),
                    eq(userContext),
                    eq(currentUser),
                    eq(auditRecordParameters)
                );
          });
        });

        describe("when regenerating rsa", () -> {
          beforeEach(() -> {
            when(credentialDataService.findMostRecent(eq("rsa")))
                .thenReturn(rsaCredential);
            CredentialRegenerateRequest rsaRegenerateRequest = new CredentialRegenerateRequest();
            rsaRegenerateRequest.setName("rsa");
            when(rsaCredential.getName()).thenReturn("rsa");
            when(rsaCredential.getCredentialType()).thenReturn("rsa");
            when(generatorService.generateRsaKeys(any(RsaGenerationParameters.class)))
                .thenReturn(mock(RsaCredentialValue.class));

            subject
                .performRegenerate(rsaRegenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
          });

          it("should generate a new rsa key pair", () -> {
            verify(credentialService)
                .save(
                    eq("rsa"),
                    eq("rsa"),
                    isA(RsaCredentialValue.class),
                    eq(null),
                    eq(Collections.emptyList()),
                    eq(true),
                    eq(userContext),
                    eq(currentUser),
                    eq(auditRecordParameters)
                );
          });
        });
      });

      describe("when regenerating a credential that does not exist", () -> {
        itThrows("an exception", EntryNotFoundException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
          passwordGenerateRequest.setName("missing_entry");

          subject.performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
        });
      });

      describe("when attempting regenerate of non-regeneratable type", () -> {
        itThrows("an exception", ParameterizedValidationException.class, () -> {
          CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
          passwordGenerateRequest.setName("unsupported");

          subject.performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
        });
      });
    });
  }
}
