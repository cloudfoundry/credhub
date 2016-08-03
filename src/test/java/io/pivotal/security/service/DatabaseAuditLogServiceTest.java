package io.pivotal.security.service;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CaController;
import io.pivotal.security.controller.v1.SecretsController;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.fake.FakeAuditRecordRepository;
import io.pivotal.security.fake.FakeSecretRepository;
import io.pivotal.security.fake.FakeTransactionManager;
import io.pivotal.security.util.CurrentTimeProvider;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonpath.matchers.JsonPathMatchers.hasJsonPath;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class DatabaseAuditLogServiceTest {

  @Autowired
  @InjectMocks
  DatabaseAuditLogService subject;

  FakeAuditRecordRepository auditRepository;

  FakeSecretRepository secretRepository;

  FakeTransactionManager transactionManager;

  @Mock
  ResourceServerTokenServices tokenServices;

  @Mock
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  SecretsController secretsController;

  @Autowired
  CaController caController;

  private SecurityContext oldContext;
  private LocalDateTime now;

  private ResponseEntity<?> responseEntity;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      transactionManager = new FakeTransactionManager();
      auditRepository = new FakeAuditRecordRepository(transactionManager);
      secretRepository = new FakeSecretRepository(transactionManager);
      subject.auditRecordRepository = auditRepository;
      subject.transactionManager = transactionManager;

      now = LocalDateTime.now();
      when(currentTimeProvider.getCurrentTime()).thenReturn(now);

      setupSecurityContext();
    });

    afterEach(() -> {
      SecurityContextHolder.setContext(oldContext);
      currentTimeProvider.reset();

      auditRepository.deleteAll();
      secretRepository.deleteAll();
    });

    describe("logging behavior", () -> {
      describe("when the operation succeeds", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              final NamedStringSecret secret = secretRepository.save(new NamedStringSecret("key").setValue("value"));
              return new ResponseEntity<>(secret, HttpStatus.OK);
            });
          });

          it("passes the request untouched", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.OK));
          });

          it("logs audit entry", () -> {
            checkAuditRecord(true);
            assertThat(secretRepository.count(), equalTo(1L));
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            auditRepository.makeDangerous();

            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              final NamedStringSecret secret = secretRepository.save(new NamedStringSecret("key").setValue("value"));
              return new ResponseEntity<>(secret, HttpStatus.OK);
            });
          });

          it("writes nothing to any database", () -> {
            assertThat(auditRepository.count(), equalTo(0L));
            assertThat(secretRepository.count(), equalTo(0L));
          });

          it("returns 500", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR));
            assertThat(responseEntity.getBody(), hasJsonPath("$.error", equalTo("The request could not be completed. Please contact your system administrator to resolve this issue.")));
          });
        });
      });

      describe("when the operation fails with an exception", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              secretRepository.save(new NamedStringSecret("key").setValue("value"));
              throw new RuntimeException("controller method failed");
            });
          });

          it("leaves the 500 response from the controller alone", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR));
          });

          it("logs failed audit entry", () -> {
            checkAuditRecord(false);
            assertThat(secretRepository.count(), equalTo(0L));
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            auditRepository.makeDangerous();

            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              secretRepository.save(new NamedStringSecret("key").setValue("value"));
              throw new RuntimeException("controller method failed");
            });
          });

          it("rolls back both original and audit repository transactions", () -> {
            assertThat(auditRepository.count(), equalTo(0L));
            assertThat(secretRepository.count(), equalTo(0L));
          });

          it("returns 500 and original error message", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR));
            assertThat(responseEntity.getBody(), hasJsonPath("$.error", equalTo("The request could not be completed. Please contact your system administrator to resolve this issue.")));
          });
        });
      });

      describe("when the operation fails with a non 200 status", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              secretRepository.save(new NamedStringSecret("key").setValue("value"));
              return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
            });
          });

          it("logs audit entry for failure", () -> {
            checkAuditRecord(false);
            assertThat(secretRepository.count(), equalTo(0L));
          });

          it("returns the non-2xx status code", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.BAD_GATEWAY));
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            auditRepository.makeDangerous();
            responseEntity = subject.performWithAuditing("credential_access", "hostName", "requestURI", () -> {
              secretRepository.save(new NamedStringSecret("key").setValue("value"));
              return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
            });
          });

          it("rolls back both original and audit repository transactions", () -> {
            assertThat(auditRepository.count(), equalTo(0L));
            assertThat(secretRepository.count(), equalTo(0L));
          });

          it("returns 500", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR));
            assertThat(responseEntity.getBody(), hasJsonPath("$.error", equalTo("The request could not be completed. Please contact your system administrator to resolve this issue.")));
          });
        });
      });
    });
  }

  private void setupSecurityContext() {
    oldContext = SecurityContextHolder.getContext();

    Authentication authentication = mock(Authentication.class);
    OAuth2AuthenticationDetails authenticationDetails = mock(OAuth2AuthenticationDetails.class);
    when(authenticationDetails.getTokenValue()).thenReturn("abcde");
    when(authentication.getDetails()).thenReturn(authenticationDetails);
    OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
    ImmutableMap<String, Object> additionalInfo = ImmutableMap.of(
        "iat", 1406568935L,
        "user_name", "marissa",
        "user_id", "12345-6789a",
        "iss", "http://localhost/uaa");
    when(accessToken.getAdditionalInformation()).thenReturn(additionalInfo);
    when(accessToken.getExpiration()).thenReturn(new Date(3333333333000L));
    when(tokenServices.readAccessToken("abcde")).thenReturn(accessToken);

    SecurityContext securityContext = mock(SecurityContext.class);
    when(securityContext.getAuthentication()).thenReturn(authentication);
    SecurityContextHolder.setContext(securityContext);
  }

  private void checkAuditRecord(boolean successFlag) {
    List<OperationAuditRecord> auditRecords = auditRepository.findAll();
    assertThat(auditRecords, hasSize(1));

    OperationAuditRecord actual = auditRecords.get(0);
    assertThat(actual.getNow(), equalTo(now.toInstant(ZoneOffset.UTC).toEpochMilli()));
    assertThat(actual.getOperation(), equalTo("credential_access"));
    assertThat(actual.getUserId(), equalTo("12345-6789a"));
    assertThat(actual.getUserName(), equalTo("marissa"));
    assertThat(actual.getUaaUrl(), equalTo("http://localhost/uaa"));
    assertThat(actual.getTokenIssued(), equalTo(1406568935L));
    assertThat(actual.getTokenExpires(), equalTo(3333333333L));
    assertThat(actual.getHostName(), equalTo("hostName"));
    assertThat(actual.getPath(), equalTo("requestURI"));
    assertThat(actual.isSuccess(), equalTo(successFlag));
  }
}