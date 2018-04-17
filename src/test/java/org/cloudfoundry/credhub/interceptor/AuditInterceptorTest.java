package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static javax.servlet.http.HttpServletRequest.CLIENT_CERT_AUTH;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class AuditInterceptorTest {
  private AuditInterceptor subject;
  private UserContextFactory userContextFactory;
  private UserContext userContext;
  private MockHttpServletResponse response;
  private MockHttpServletRequest request;
  private CEFAuditRecord auditRecord;

  @Before
  public void setup() {
    userContextFactory = mock(UserContextFactory.class);
    userContext = mock(UserContext.class);
    auditRecord = new CEFAuditRecord();

    subject = new AuditInterceptor(
        userContextFactory,
        auditRecord
    );
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    final Authentication authentication = mock(Authentication.class);
    request.setUserPrincipal(authentication);

    userContext = mock(UserContext.class);
    when(userContextFactory.createUserContext(any())).thenReturn(userContext);
    when(userContext.getActor()).thenReturn("user");
    when(userContext.getAuthMethod()).thenReturn(CLIENT_CERT_AUTH);
  }

  @Test
  public void afterCompletion_returnsIfNoUserIsPresent() {
    request.setUserPrincipal(null);

    subject.afterCompletion(request, response, null, null);

    verify(userContextFactory, never()).createUserContext(null);
  }

  @Test
  public void afterCompletion_populatesTheCEFLogObject() {
    Authentication authentication = mock(Authentication.class);
    when(authentication.getName()).thenReturn("foo");
    request.setUserPrincipal(authentication);
    request.setAuthType(CLIENT_CERT_AUTH);
    response.setStatus(200);

    subject.afterCompletion(request, response, null, null);
    assertThat(auditRecord.getUsername(), is(equalTo("foo")));
    assertThat(auditRecord.getHttpStatusCode(), is(equalTo(200)));
    assertThat(auditRecord.getResult(), is(equalTo("success")));
    assertThat(auditRecord.getAuthMechanism(), is(equalTo(CLIENT_CERT_AUTH)));
  }

  @Test
  public void preHandle_populatesTheCEFLogObject() {
    request.setAuthType(CLIENT_CERT_AUTH);
    request.setRequestURI("/foo/bar");
    request.setQueryString("baz=qux&hi=bye");
    request.setMethod("GET");
    subject.preHandle(request, response, null);
    assertThat(auditRecord.getRequestPath(), is(equalTo("/foo/bar?baz=qux&hi=bye")));
    assertThat(auditRecord.getRequestMethod(), is(equalTo("GET")));
  }
}
