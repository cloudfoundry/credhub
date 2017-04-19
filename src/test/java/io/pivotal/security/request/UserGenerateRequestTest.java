package io.pivotal.security.request;

import io.pivotal.security.secret.User;
import io.pivotal.security.service.GeneratorService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Arrays;

import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGenerateRequestTest {

  private GeneratorService generatorService;
  private UserGenerateRequest subject;
  private AccessControlEntry accessControlEntry;
  private User user;

  @Before
  public void beforeEach() {
    generatorService = mock(GeneratorService.class);
    user = new User("fake-user", "fake-password");
    when(generatorService.generateUser(any(UserGenerationParameters.class))).thenReturn(user);
    accessControlEntry = new AccessControlEntry("test-actor",
        Arrays.asList(READ, WRITE));
    subject = new UserGenerateRequest();
    subject.setType("user");
    subject.setName("test-name");
    subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
    subject.setOverwrite(true);
  }

  @Test
  public void generateSetRequest_whenValueNull_createsAndCopiesSetRequestGeneratingUsernameAndPassword() {
    BaseSecretSetRequest setRequest = subject.generateSetRequest(generatorService);

    assertThat(setRequest.getType(), equalTo("user"));
    assertThat(setRequest.getName(), equalTo("test-name"));
    assertTrue(setRequest.isOverwrite());
    assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
    assertThat(((UserSetRequest) setRequest)
      .getUserSetRequestFields()
      .getPassword(), equalTo("fake-password"));
    assertThat(((UserSetRequest) setRequest)
      .getUserSetRequestFields()
      .getUsername(), equalTo("fake-user"));
    ArgumentCaptor<UserGenerationParameters> captor =
      ArgumentCaptor.forClass(UserGenerationParameters.class);

    verify(generatorService).generateUser(captor.capture());

    StringGenerationParameters passwordParameters = new StringGenerationParameters();

    StringGenerationParameters usernameParameters = new StringGenerationParameters();
    usernameParameters.setExcludeNumber(true);
    usernameParameters.setLength(20);

    assertThat(captor.getValue().getPasswordGenerationParameters(),
      samePropertyValuesAs(passwordParameters));
    assertThat(captor.getValue().getUsernameGenerationParameters(),
      samePropertyValuesAs(usernameParameters));
  }

  @Test
  public void generateSetRequest_whenValueNonNull_createsAndCopiesSetRequestGeneratingOnlyPassword() {
    UserValue userValue = new UserValue();
    userValue.setUsername("specified-user");
    subject.setValue(userValue);

    UserGenerationParameters parameters = new UserGenerationParameters();
    parameters.setUsernameGenerationParameters(null);

    user.setUsername(null);

    when(generatorService.generateUser(same(parameters))).thenReturn(user);
    BaseSecretSetRequest setRequest = subject.generateSetRequest(generatorService);

    assertThat(setRequest.getType(), equalTo("user"));
    assertThat(setRequest.getName(), equalTo("test-name"));
    assertTrue(setRequest.isOverwrite());
    assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
    assertThat(((UserSetRequest) setRequest)
      .getUserSetRequestFields()
      .getPassword(), equalTo("fake-password"));
    assertThat(((UserSetRequest) setRequest)
      .getUserSetRequestFields()
      .getUsername(), equalTo("specified-user"));
    ArgumentCaptor<UserGenerationParameters> captor =
      ArgumentCaptor.forClass(UserGenerationParameters.class);

    verify(generatorService).generateUser(captor.capture());

    StringGenerationParameters passwordParameters = new StringGenerationParameters();

    assertThat(captor.getValue().getPasswordGenerationParameters(),
      samePropertyValuesAs(passwordParameters));
    assertThat(captor.getValue().getUsernameGenerationParameters(), is(nullValue()));
  }
}
