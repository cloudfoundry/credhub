package io.pivotal.security.request;

import io.pivotal.security.credential.UserCredentialValue;
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
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGenerateRequestTest {

  private GeneratorService generatorService;
  private UserGenerateRequest subject;
  private AccessControlEntry accessControlEntry;

  @Before
  public void beforeEach() {
    generatorService = mock(GeneratorService.class);
    accessControlEntry = new AccessControlEntry("test-actor",
        Arrays.asList(READ, WRITE));
    subject = new UserGenerateRequest();
    subject.setType("user");
    subject.setName("test-name");
    subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
    subject.setOverwrite(true);
  }

  @Test
  public void generateSetRequest_withoutAUsername_createsAndCopiesSetRequestGeneratingUsernameAndPassword() {
    UserCredentialValue expectedUser = new UserCredentialValue("fake-user", "fake-password", "fake-salt");
    when(generatorService.generateUser(any(String.class), any(StringGenerationParameters.class)))
        .thenReturn(expectedUser);

    UserSetRequest setRequest = (UserSetRequest) subject.generateSetRequest(generatorService);

    assertThat(setRequest.getType(), equalTo("user"));
    assertThat(setRequest.getName(), equalTo("test-name"));
    assertTrue(setRequest.isOverwrite());
    assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
    assertThat(setRequest.getUserValue(), equalTo(expectedUser));
    ArgumentCaptor<StringGenerationParameters> captor =
      ArgumentCaptor.forClass(StringGenerationParameters.class);

    verify(generatorService, times(1)).generateUser(eq(null), captor.capture());

    StringGenerationParameters actualPasswordParameters = captor.getValue();
    StringGenerationParameters passwordParameters = new StringGenerationParameters();

    assertThat(actualPasswordParameters, samePropertyValuesAs(passwordParameters));
  }

  @Test
  public void generateSetRequest_withAStaticUsername_createsAndCopiesSetRequestGeneratingOnlyPassword() {
    UsernameValue usernameValue = new UsernameValue();
    usernameValue.setUsername("specified-username");
    subject.setValue(usernameValue);

    UserCredentialValue expectedUser = new UserCredentialValue("fake-user", "fake-password", "fake-salt");
    when(generatorService.generateUser(any(String.class), any(StringGenerationParameters.class)))
        .thenReturn(expectedUser);

    UserSetRequest setRequest = (UserSetRequest) subject.generateSetRequest(generatorService);

    assertThat(setRequest.getType(), equalTo("user"));
    assertThat(setRequest.getName(), equalTo("test-name"));
    assertTrue(setRequest.isOverwrite());
    assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));

    assertThat(setRequest.getUserValue(), equalTo(expectedUser));

    ArgumentCaptor<StringGenerationParameters> captor = ArgumentCaptor.forClass(StringGenerationParameters.class);

    verify(generatorService).generateUser(eq("specified-username"), captor.capture());

    StringGenerationParameters passwordParameters = new StringGenerationParameters();

    assertThat(captor.getValue(), samePropertyValuesAs(passwordParameters));
  }

  @Test
  public void generateSetRequest_WithPasswordGenerationParams_generatesPasswordWithParameters() {
    StringGenerationParameters passwordGenerationParams = new StringGenerationParameters()
        .setExcludeNumber(true)
        .setIncludeSpecial(true);

    when(generatorService.generateUser(any(String.class), eq(passwordGenerationParams)))
        .thenReturn(new UserCredentialValue("fake-generated-username", "fake-generated-password", "fake-salt"));

    subject.setPasswordGenerationParameters(passwordGenerationParams);

    final UserSetRequest setRequest = (UserSetRequest) subject.generateSetRequest(generatorService);
    final String password = setRequest.getUserValue().getPassword();

    assertThat(password, equalTo("fake-generated-password"));

    ArgumentCaptor<StringGenerationParameters> passwordParametersCaptor = ArgumentCaptor.forClass(StringGenerationParameters.class);

    verify(generatorService, times(1)).generateUser(any(String.class), passwordParametersCaptor.capture());

    final StringGenerationParameters genParams = passwordParametersCaptor.getValue();
    assertThat(genParams, samePropertyValuesAs(passwordGenerationParams));
  }
}
