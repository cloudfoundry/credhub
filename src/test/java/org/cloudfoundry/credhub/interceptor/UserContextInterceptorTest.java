package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

import static junit.framework.TestCase.assertFalse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class UserContextInterceptorTest {
  private UserContextInterceptor subject;
  private UserContext userContext;
  private UserContextFactory userContextFactory;
  private UserContextHolder userContextHolder;
  private HttpServletRequest request;

  @Before
  public void setup() {
    userContextFactory = mock(UserContextFactory.class);
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();

    subject = new UserContextInterceptor(userContextFactory, userContextHolder);

    when(userContextFactory.createUserContext(any())).thenReturn(userContext);
    request = mock(HttpServletRequest.class);
  }

  @Test
  public void preHandle_setsUserContextFromPrincipal() throws Exception {
    when(request.getUserPrincipal()).thenReturn(mock(Authentication.class));
    subject.preHandle(request, null, null);

    assertThat(userContextHolder.getUserContext(), equalTo(userContext));
  }

  @Test
  public void preHandle_ReturnsFalseWhenNoPrincipal() throws Exception {
    when(request.getUserPrincipal()).thenReturn(null);
    boolean result = subject.preHandle(request, null, null);
    assertFalse(result);
  }
}
