package org.cloudfoundry.credhub.interceptor;

import javax.servlet.http.HttpServletRequest;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.assertFalse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class UserContextInterceptorTest {
  private UserContextInterceptor subject;
  private UserContext userContext;
  private UserContextFactory userContextFactory;
  private UserContextHolder userContextHolder;
  private HttpServletRequest request;
  private MockHttpServletResponse response;

  @Before
  public void setup() {
    userContextFactory = mock(UserContextFactory.class);
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();

    subject = new UserContextInterceptor(userContextFactory, userContextHolder);

    when(userContextFactory.createUserContext(any())).thenReturn(userContext);
    request = mock(HttpServletRequest.class);
    response = new MockHttpServletResponse();
  }

  @Test
  public void preHandle_setsUserContextFromPrincipal() throws Exception {
    when(request.getUserPrincipal()).thenReturn(mock(Authentication.class));
    subject.preHandle(request, response, new Object());

    assertThat(userContextHolder.getUserContext(), equalTo(userContext));
  }

  @Test
  public void preHandle_ReturnsFalseWhenNoPrincipal() throws Exception {
    when(request.getUserPrincipal()).thenReturn(null);
    final boolean result = subject.preHandle(request, response, new Object());
    assertFalse(result);
  }
}
