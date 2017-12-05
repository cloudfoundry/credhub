package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.servlet.http.HttpServletRequest;

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

  @Before
  public void setup() {
    userContextFactory = mock(UserContextFactory.class);
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();

    subject = new UserContextInterceptor(userContextFactory, userContextHolder);

    when(userContextFactory.createUserContext(any())).thenReturn(userContext);
  }

  @Test
  public void preHandle_setsUserContextFromPrincipal() throws Exception {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    subject.preHandle(request, null, null);

    assertThat(userContextHolder.getUserContext(), equalTo(userContext));
  }
}
