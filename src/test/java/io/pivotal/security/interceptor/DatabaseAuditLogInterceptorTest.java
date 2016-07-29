package io.pivotal.security.interceptor;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CaController;
import io.pivotal.security.controller.v1.SecretsController;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.AuditRecordRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.*;
import static com.jayway.jsonpath.matchers.JsonPathMatchers.hasJsonPath;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class DatabaseAuditLogInterceptorTest {

  @Autowired
  @InjectMocks
  DatabaseAuditLogInterceptor subject;

  @Autowired
  AuditRecordRepository auditRepository;

  @Autowired
  SecretRepository secretRepository;

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
  private MockHttpServletRequest httpServletRequest;
  private MockHttpServletResponse httpServletResponse;
  HandlerMethod getHandler;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      httpServletRequest = new MockHttpServletRequest();
      httpServletRequest.setServerName("hostName");
      httpServletRequest.setServletPath("servletPath");

      httpServletResponse = new MockHttpServletResponse();
      httpServletResponse.setStatus(HttpServletResponse.SC_OK);

      now = LocalDateTime.now();
      when(currentTimeProvider.getCurrentTime()).thenReturn(now);

      setupSecurityContext();

      auditRepository.deleteAll();
      secretRepository.deleteAll();

      getHandler = new HandlerMethod(secretsController, "get", String.class);
    });

    afterEach(() -> {
      SecurityContextHolder.setContext(oldContext);
      currentTimeProvider.reset();
    });

    describe("logging behavior", () -> {
      describe("when the operation succeeds", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            subject.preHandle(httpServletRequest, httpServletResponse, null);
            secretRepository.save(new NamedStringSecret("key").setValue("value"));
            subject.postHandle(httpServletRequest, httpServletResponse, null, null);

            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, null);
          });

          it("passes the request untouched", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_OK));
          });

          it("logs audit entry", () -> {
            checkAuditRecord(true);
            checkSecretRecord(1);
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            AuditRecordRepository mockAuditRepository = mock(AuditRecordRepository.class);
            doThrow(new RuntimeException("audit save interruptus")).when(mockAuditRepository).save(any(OperationAuditRecord.class));
            subject.auditRecordRepository = mockAuditRepository;

            subject.preHandle(httpServletRequest, httpServletResponse, null);
            secretRepository.save(new NamedStringSecret("key").setValue("value"));
            httpServletResponse.getOutputStream().write("garbage".getBytes());
            subject.postHandle(httpServletRequest, httpServletResponse, null, null);
            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, null);
          });

          it("writes nothing to any database", () -> {
            assertThat(auditRepository.findAll(), hasSize(0));
            checkSecretRecord(0);
          });

          it("returns 500", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR));
            assertThat(httpServletResponse.getContentAsString(), hasJsonPath("$.error", equalTo("Dan's error message")));
          });
        });
      });

      describe("when the operation fails with an exception", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            subject.preHandle(httpServletRequest, httpServletResponse, null);
            secretRepository.save(new NamedStringSecret("key").setValue("value"));
            httpServletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, new Exception("controller method failed"));
          });

          it("leaves the 500 response from the controller alone", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR));
          });

          it("logs failed audit entry", () -> {
            checkAuditRecord(false);
            checkSecretRecord(0);
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            AuditRecordRepository mockAuditRepository = mock(AuditRecordRepository.class);
            doThrow(new RuntimeException("audit save interruptus")).when(mockAuditRepository).save(any(OperationAuditRecord.class));
            subject.auditRecordRepository = mockAuditRepository;
            subject.transactionManager = mock(PlatformTransactionManager.class);

            subject.preHandle(httpServletRequest, httpServletResponse, null);
            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, new Exception("controller method failed"));
          });

          it("rolls back both original and audit repository transactions", () -> {
            verify(subject.transactionManager, times(2)).rollback(any(TransactionStatus.class));
          });

          it("returns 500 and original error message", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR));
            assertThat(httpServletResponse.getContentAsString(), hasJsonPath("$.error", equalTo("Dan's error message")));
          });
        });
      });

      describe("when the operation fails with a non 200 status", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            subject.preHandle(httpServletRequest, httpServletResponse, null);
            secretRepository.save(new NamedStringSecret("key").setValue("value"));
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            subject.postHandle(httpServletRequest, httpServletResponse, null, null);
            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, null);
          });

          it("logs audit entry for failure", () -> {
            checkAuditRecord(false);
            checkSecretRecord(0);
          });

          it("returns the non-2xx status code", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_BAD_GATEWAY));
          });
        });

        describe("when the audit fails", () -> {
          beforeEach(() -> {
            AuditRecordRepository mockAuditRepository = mock(AuditRecordRepository.class);
            doThrow(new RuntimeException("audit save interruptus")).when(mockAuditRepository).save(any(OperationAuditRecord.class));
            subject.auditRecordRepository = mockAuditRepository;

            subject.transactionManager = mock(PlatformTransactionManager.class);

            subject.preHandle(httpServletRequest, httpServletResponse, null);
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            subject.postHandle(httpServletRequest, httpServletResponse, null, null);
            subject.afterCompletion(httpServletRequest, httpServletResponse, getHandler, null);
          });

          it("rolls back both original and audit repository transactions", () -> {
            verify(subject.transactionManager, times(2)).rollback(any(TransactionStatus.class));
          });

          it("returns 500", () -> {
            assertThat(httpServletResponse.getStatus(), equalTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR));
            assertThat(httpServletResponse.getContentAsString(), hasJsonPath("$.error", equalTo("Dan's error message")));
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
    assertThat(actual.getPath(), equalTo("servletPath"));
    assertThat(actual.isSuccess(), equalTo(successFlag));
  }

  private void checkSecretRecord(int expectedQuantity) {
    assertThat(secretRepository.findAll().size(), equalTo(expectedQuantity));
  }
}