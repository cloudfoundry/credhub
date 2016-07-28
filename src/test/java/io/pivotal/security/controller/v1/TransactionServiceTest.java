package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.InMemoryAuditRecordRepository;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
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

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class TransactionServiceTest {

  @Autowired
  @InjectMocks
  TransactionService subject;

  @Autowired
  InMemoryAuditRecordRepository auditRepository;

  @Autowired
  InMemorySecretRepository secretRepository;

  @Mock
  ResourceServerTokenServices tokenServices;

  @Mock
  CurrentTimeProvider currentTimeProvider;

  private SecurityContext oldContext;
  private LocalDateTime now;
  private HttpServletRequest httpServletRequest;
  private Supplier<ResponseEntity> controllerBehavior;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      httpServletRequest = mock(HttpServletRequest.class);

      now = LocalDateTime.now();
      when(currentTimeProvider.getCurrentTime()).thenReturn(now);

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
      when(httpServletRequest.getServerName()).thenReturn("hostName");
      when(httpServletRequest.getPathInfo()).thenReturn("pathInfo");

      auditRepository.deleteAll();
      secretRepository.deleteAll();
    });

    afterEach(() -> {
      SecurityContextHolder.setContext(oldContext);
      currentTimeProvider.reset();
    });

    describe("logging behavior", () -> {
      ResponseEntity successResponseEntity = new ResponseEntity(HttpStatus.OK);
      ResponseEntity failureResponseEntity = new ResponseEntity(HttpStatus.NOT_FOUND);

      Block auditFailsSharedBehavior = () -> {
        beforeEach(() -> {
          InMemoryAuditRecordRepository mockAuditRepository = mock(InMemoryAuditRecordRepository.class);
          doThrow(new RuntimeException("audit save interruptus")).when(mockAuditRepository).save(any(OperationAuditRecord.class));
          subject.auditRepository = mockAuditRepository;
        });

        it("writes nothing to the database", () -> {
          subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
          assertThat(auditRepository.findAll(), hasSize(0));
          checkSecretRecord(0);
        });

        it("returns 500", () -> {
          assertThat(subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior), equalTo(new ResponseEntity<>("Dan's error message", HttpStatus.INTERNAL_SERVER_ERROR)));
        });
      };

      describe("when the operation succeeds", () -> {
        beforeEach(() -> {
          controllerBehavior = makeControllerBehaviorLambda(() -> successResponseEntity);
        });

        describe("when the audit succeeds", () -> {
          it("invokes the lambda and returns the result", () -> {
            ResponseEntity response = subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            assertThat(response, sameInstance(successResponseEntity));
          });

          it("logs audit entry", () -> {
            subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            checkAuditRecord(true);
            checkSecretRecord(1);
          });
        });

        describe("when the audit fails", auditFailsSharedBehavior);
      });

      describe("when the operation fails with an exception", () -> {
        beforeEach(() -> {
          controllerBehavior = makeControllerBehaviorLambda(() -> {
            throw new RuntimeException("controller behavior interruptus");
          });
        });

        describe("when the audit succeeds", () -> {
          it("returns 500", () -> {
            ResponseEntity response = subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            assertThat(response.getStatusCode(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR));
          });

          it("logs failed audit entry", () -> {
            subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            checkAuditRecord(false);
            checkSecretRecord(0);
          });
        });

        describe("when the audit fails", auditFailsSharedBehavior);
      });

      describe("when the operation fails with a non 200 status", () -> {
        beforeEach(() -> {
          controllerBehavior = makeControllerBehaviorLambda(() -> failureResponseEntity);
        });

        describe("when the audit succeeds", () -> {
          it("logs failed audit entry when a non-2xx HTTP status code is returned", () -> {
            subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            checkAuditRecord(false);
            checkSecretRecord(0);
          });

          it("returns the non-2xx status code", () -> {
            ResponseEntity response = subject.performWithLogging("testOperation", httpServletRequest, controllerBehavior);
            assertThat(response, sameInstance(failureResponseEntity));
          });
        });

        describe("when the audit fails", auditFailsSharedBehavior);
      });
    });
  }

  private void checkAuditRecord(boolean successFlag) {
    List<OperationAuditRecord> auditRecords = auditRepository.findAll();
    assertThat(auditRecords, hasSize(1));

    OperationAuditRecord actual = auditRecords.get(0);
    assertThat(actual.getNow(), equalTo(now.toInstant(ZoneOffset.UTC).toEpochMilli()));
    assertThat(actual.getOperation(), equalTo("testOperation"));
    assertThat(actual.getUserId(), equalTo("12345-6789a"));
    assertThat(actual.getUserName(), equalTo("marissa"));
    assertThat(actual.getUaaUrl(), equalTo("http://localhost/uaa"));
    assertThat(actual.getTokenIssued(), equalTo(1406568935L));
    assertThat(actual.getTokenExpires(), equalTo(3333333333L));
    assertThat(actual.getHostName(), equalTo("hostName"));
    assertThat(actual.getPath(), equalTo("pathInfo"));
    assertThat(actual.isSuccess(), equalTo(successFlag));
  }

  private void checkSecretRecord(int expectedQuantity) {
    assertThat(secretRepository.findAll().size(), equalTo(expectedQuantity));
  }

  private Supplier<ResponseEntity> makeControllerBehaviorLambda(Supplier<ResponseEntity> innerBehavior) {
    return () -> {
      secretRepository.save(new NamedStringSecret("key").setValue("value"));
      return innerBehavior.get();
    };
  }
}