package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.view.ResponseError;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNot.not;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class RegenerateServiceTest {

  private SecretDataService secretDataService;
  private GenerateService generateService;
  private RegenerateService subject;

  private NamedPasswordSecret namedPasswordSecret;
  private NamedSshSecret namedSshSecret;
  private NamedRsaSecret namedRsaSecret;
  private NamedCertificateSecret secretOfUnsupportedType;
  private PasswordGenerationParameters expectedParameters;
  private ResponseEntity responseEntity;
  private ResponseError expectedResponseEntity;

  {
    beforeEach(() -> {
      secretDataService = mock(SecretDataService.class);
      generateService = mock(GenerateService.class);
      namedPasswordSecret = mock(NamedPasswordSecret.class);
      namedSshSecret = mock(NamedSshSecret.class);
      namedRsaSecret = mock(NamedRsaSecret.class);


      when(secretDataService.findMostRecent(eq("unsupported")))
          .thenReturn(secretOfUnsupportedType);
      when(generateService
          .performGenerate(isA(AuditRecordBuilder.class), isA(BaseSecretGenerateRequest.class)))
          .thenReturn(new ResponseEntity(HttpStatus.OK));
      secretOfUnsupportedType = new NamedCertificateSecret();
      subject = new RegenerateService(secretDataService, generateService);
    });

    describe("#performRegenerate", () -> {
      describe("password", () -> {
        beforeEach(() -> {
          when(secretDataService.findMostRecent(eq("password")))
              .thenReturn(namedPasswordSecret);
          SecretRegenerateRequest passwordGenerateRequest = new SecretRegenerateRequest()
              .setName("password");
          expectedParameters = new PasswordGenerationParameters()
              .setExcludeLower(true)
              .setExcludeUpper(true)
              .setLength(20);
          when(namedPasswordSecret.getName()).thenReturn("password");
          when(namedPasswordSecret.getSecretType()).thenReturn("password");
          when(namedPasswordSecret.getGenerationParameters())
              .thenReturn(expectedParameters);

          expectedResponseEntity = new ResponseError("some error");
          responseEntity = subject
              .performRegenerate(mock(AuditRecordBuilder.class), passwordGenerateRequest);
        });
        describe("when regenerating password", () -> {

          it("should return non null response", () -> {
            assertThat(responseEntity, not(nullValue()));
          });

          it("should generate a new password", () -> {
            ArgumentCaptor<BaseSecretGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseSecretGenerateRequest.class);

            verify(generateService)
                .performGenerate(isA(AuditRecordBuilder.class), generateRequestCaptor.capture());

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
            when(namedPasswordSecret.getGenerationParameters())
                .thenReturn(null);
          });

          itThrowsWithMessage(
              "it returns an error",
              ParameterizedValidationException.class,
              "error.cannot_regenerate_non_generated_password",
              () -> {
                SecretRegenerateRequest passwordGenerateRequest = new SecretRegenerateRequest()
                    .setName("password");

                responseEntity = subject
                    .performRegenerate(mock(AuditRecordBuilder.class), passwordGenerateRequest);
              });
        });
      });

      describe("ssh & rsa", () -> {
        describe("when regenerating ssh", () -> {
          beforeEach(() -> {
            when(secretDataService.findMostRecent(eq("ssh")))
                .thenReturn(namedSshSecret);
            SecretRegenerateRequest sshRegenerateRequest = new SecretRegenerateRequest()
                .setName("ssh");
            when(namedSshSecret.getName()).thenReturn("ssh");
            when(namedSshSecret.getSecretType()).thenReturn("ssh");

            responseEntity = subject
                .performRegenerate(mock(AuditRecordBuilder.class), sshRegenerateRequest);
          });

          it("should return non null response", () -> {
            assertThat(responseEntity, not(nullValue()));
          });

          it("should generate a new ssh key pair", () -> {
            ArgumentCaptor<BaseSecretGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseSecretGenerateRequest.class);

            verify(generateService)
                .performGenerate(isA(AuditRecordBuilder.class), generateRequestCaptor.capture());

            SshGenerateRequest generateRequest = (SshGenerateRequest) generateRequestCaptor
                .getValue();

            assertThat(generateRequest.getName(), equalTo("ssh"));
            assertThat(generateRequest.getType(), equalTo("ssh"));
          });
        });

        describe("when regenerating rsa", () -> {
          beforeEach(() -> {
            when(secretDataService.findMostRecent(eq("rsa")))
                .thenReturn(namedRsaSecret);
            SecretRegenerateRequest rsaRegenerateRequest = new SecretRegenerateRequest()
                .setName("rsa");
            when(namedRsaSecret.getName()).thenReturn("rsa");
            when(namedRsaSecret.getSecretType()).thenReturn("rsa");

            responseEntity = subject
                .performRegenerate(mock(AuditRecordBuilder.class), rsaRegenerateRequest);
          });

          it("should return non null response", () -> {
            assertThat(responseEntity, not(nullValue()));
          });

          it("should generate a new rsa key pair", () -> {
            ArgumentCaptor<BaseSecretGenerateRequest> generateRequestCaptor =
                ArgumentCaptor.forClass(BaseSecretGenerateRequest.class);

            verify(generateService)
                .performGenerate(isA(AuditRecordBuilder.class), generateRequestCaptor.capture());

            RsaGenerateRequest generateRequest = (RsaGenerateRequest) generateRequestCaptor
                .getValue();

            assertThat(generateRequest.getName(), equalTo("rsa"));
            assertThat(generateRequest.getType(), equalTo("rsa"));
          });
        });
      });

      describe("when regenerating something of a type we don't recognise yet", () -> {
        it("should return non null response", () -> {
          SecretRegenerateRequest passwordGenerateRequest = new SecretRegenerateRequest()
              .setName("unsupported");

          ResponseEntity responseEntity =
              subject.performRegenerate(mock(AuditRecordBuilder.class), passwordGenerateRequest);

          assertThat(responseEntity, nullValue());
        });
      });
    });
  }
}
