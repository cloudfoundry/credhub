package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException;
import org.cloudfoundry.credhub.exceptions.ReadOnlyException;
import org.cloudfoundry.credhub.variables.ManagementVariables;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

@RunWith(SpringRunner.class)
public class ManagementInterceptorTest {
  private ManagementInterceptor subject;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @Before
  public void setup() {
    subject = new ManagementInterceptor();
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  @After
  public void tearDown() {
    ManagementVariables.readOnlyMode = false;
  }

  @Test(expected = InvalidRemoteAddressException.class)
  public void preHandle_throwsAnExceptionWhenRemoteAddressDoesNotMatchLocalAddress(){
    request.setRemoteAddr("10.0.0.1");
    request.setLocalAddr("127.0.0.1");
    request.setRequestURI("/management");
    subject.preHandle(request, response, null);
    assertThat(response.getStatus(), is(401));
  }

  @Test
  public void preHandle_doesNotThrowAnExceptionWhenRemoteAddressMatchesLocalAddress(){
    request.setRemoteAddr("127.0.0.1");
    request.setLocalAddr("127.0.0.1");
    request.setRequestURI("/management");
    subject.preHandle(request, response, null);
  }

  @Test(expected = ReadOnlyException.class)
  public void preHandle_throwsAnExceptionWhenTheRequestMethodIsNotGetInReadOnlyMode(){
    ManagementVariables.readOnlyMode = true;
    request.setRequestURI("/api/v1/data");
    request.setMethod("POST");
    subject.preHandle(request, response, null);
    assertThat(response.getStatus(), is(503));
  }

  @Test
  public void preHandle_throwsNoExceptionWhenTheRequestMethodGetInReadOnlyMode(){
    ManagementVariables.readOnlyMode = true;
    request.setRequestURI("/api/v1/data");
    request.setMethod("GET");
    subject.preHandle(request, response, null);
  }

  @Test
  public void preHandle_postsToManagementStillWork(){
    ManagementVariables.readOnlyMode = true;
    request.setRequestURI("/management");
    request.setMethod("POST");
    subject.preHandle(request, response, null);
  }

  @Test
  public void preHandle_continuesToServePostsToInterpolate(){
    ManagementVariables.readOnlyMode = true;
    request.setRequestURI("/interpolate");
    request.setMethod("POST");
    subject.preHandle(request, response, null);
  }
}
