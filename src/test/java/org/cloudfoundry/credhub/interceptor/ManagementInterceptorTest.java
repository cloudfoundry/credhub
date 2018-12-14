package org.cloudfoundry.credhub.interceptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException;
import org.cloudfoundry.credhub.exceptions.ReadOnlyException;
import org.cloudfoundry.credhub.registry.ManagementRegistry;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class ManagementInterceptorTest {
  private ManagementInterceptor subject;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @Autowired
  private ManagementRegistry managementRegistry;

  @Before
  public void setup() {
    subject = new ManagementInterceptor(managementRegistry);
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();

    managementRegistry.setReadOnlyMode(false);
  }

  @After
  public void tearDown() {
    managementRegistry.setReadOnlyMode(false);
  }

  @Test(expected = InvalidRemoteAddressException.class)
  public void preHandle_throwsAnExceptionWhenRemoteAddressDoesNotMatchLocalAddress() {
    request.setRemoteAddr("10.0.0.1");
    request.setLocalAddr("127.0.0.1");
    request.setRequestURI("/management");
    subject.preHandle(request, response, new Object());
    assertThat(response.getStatus(), is(401));
  }

  @Test
  public void preHandle_doesNotThrowAnExceptionWhenRemoteAddressMatchesLocalAddress() {
    request.setRemoteAddr("127.0.0.1");
    request.setLocalAddr("127.0.0.1");
    request.setRequestURI("/management");
    subject.preHandle(request, response, new Object());
  }

  @Test(expected = ReadOnlyException.class)
  public void preHandle_throwsAnExceptionWhenTheRequestMethodIsNotGetInReadOnlyMode() {
    managementRegistry.setReadOnlyMode(true);
    request.setRequestURI("/api/v1/data");
    request.setMethod("POST");
    subject.preHandle(request, response, new Object());
    assertThat(response.getStatus(), is(503));
  }

  @Test
  public void preHandle_throwsNoExceptionWhenTheRequestMethodGetInReadOnlyMode() {
    managementRegistry.setReadOnlyMode(true);
    request.setRequestURI("/api/v1/data");
    request.setMethod("GET");
    subject.preHandle(request, response, new Object());
  }

  @Test
  public void preHandle_postsToManagementStillWork() {
    managementRegistry.setReadOnlyMode(true);
    request.setRequestURI("/management");
    request.setMethod("POST");
    subject.preHandle(request, response, new Object());
  }

  @Test
  public void preHandle_continuesToServePostsToInterpolate() {
    managementRegistry.setReadOnlyMode(true);
    request.setRequestURI("/interpolate");
    request.setMethod("POST");
    subject.preHandle(request, response, new Object());
  }
}
