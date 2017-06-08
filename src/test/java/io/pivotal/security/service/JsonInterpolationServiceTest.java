package io.pivotal.security.service;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.InvalidObjectException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.JsonHelper.parse;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class JsonInterpolationServiceTest {

  private JsonInterpolationService subject;
  private DocumentContext response;
  private List<EventAuditRecordParameters> eventAuditRecordParameters;

  @Before
  public void beforeEach() {
    subject = new JsonInterpolationService(new JsonContextFactory());
    eventAuditRecordParameters = new ArrayList<>();
  }

  @Test
  public void interpolateCredHubReferences_replacesTheCredHubRefWithSomethingElse() throws Exception {
    setupValidRequest();

    Map<String, Object> firstCredentialsBlock = response
        .read("$.pp-config-server[0].credentials");
    Map<String, Object> secondCredentialsBlock = response
        .read("$.pp-config-server[1].credentials");
    Map<String, Object> secondServiceCredentials = response
        .read("$.pp-something-else[0].credentials");

    assertThat(firstCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(firstCredentialsBlock.size(), equalTo(1));
    assertThat(firstCredentialsBlock.get("secret1"), equalTo("secret1-value"));

    assertThat(secondCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(secondCredentialsBlock.size(), equalTo(1));
    assertThat(secondCredentialsBlock.get("secret2"), equalTo("secret2-value"));

    assertThat(secondServiceCredentials.get("credhub-ref"), nullValue());
    assertThat(secondServiceCredentials.size(), equalTo(2));
    assertThat(secondServiceCredentials.get("secret3-1"), equalTo("secret3-1-value"));
    assertThat(secondServiceCredentials.get("secret3-2"), equalTo("secret3-2-value"));
  }

  @Test
  public void interpolateCredHubReferences_updatesTheEventAuditRecordParameters() throws Exception {
    setupValidRequest();

    assertThat(eventAuditRecordParameters, hasSize(3));
    assertThat(eventAuditRecordParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred1")),
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred2")),
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred3"))));
  }

  @Test
  public void interpolateCredHubReferences_whenAReferencedCredentialIsNotJsonType_itThrowsAnException() throws Exception {
      String inputJson = "{"
          + "  \"pp-config-server\": ["
          + "    {"
          + "      \"credentials\": {"
          + "        \"credhub-ref\": \"((/password_cred))\""
          + "      },"
          + "      \"label\": \"pp-config-server\""
          + "    }"
          + "  ]"
          + "}";

      PasswordCredential passwordCredential = mock(PasswordCredential.class);

      CredentialDataService mockCredentialDataService = mock(CredentialDataService.class);

      doReturn(
          passwordCredential
      ).when(mockCredentialDataService).findMostRecent("/password_cred");

      try {
        subject.interpolateCredHubReferences(inputJson, mockCredentialDataService,
            eventAuditRecordParameters);
      } catch (ParameterizedValidationException exception) {
        assertThat(exception.getMessage(), equalTo("error.invalid_interpolation_type"));
      }
  }

  @Test
  public void interpolateCredHubReferences_whenAReferencedCredentialDoesNotExist_itThrowsAnException() throws Exception {
    String inputJson = "{"
        + "  \"pp-config-server\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/missing_cred))\""
        + "      },"
        + "      \"label\": \"pp-config-server\""
        + "    }"
        + "  ]"
        + "}";

    CredentialDataService mockCredentialDataService = mock(CredentialDataService.class);

    doReturn(
        null
    ).when(mockCredentialDataService).findMostRecent("/missing_cred");

    try {
      subject.interpolateCredHubReferences(inputJson, mockCredentialDataService,
          eventAuditRecordParameters);
    } catch (InvalidObjectException exception) {
      assertThat(exception.getMessage(), equalTo("error.invalid_access"));
    }
  }

  @Test
  public void interpolateCredHubReferences_whenTheServicePropertiesLackCredentials_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"blah\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyHasNoRefs_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": {"
        + "      \"key\": \"((value))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyIsFormattedUnexpectedly_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"foo\": {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred1))\""
        + "       }"
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void interpolateCredHubReferences_whenThePropertiesAreNotAHash_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [\"what is this?\"]"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsAreNotAHashInAnArray_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": \"moose\","
        + "    \"label\": \"squirrel\""
        + "  }]"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void interpolateCredHubReferences_whenPropertiesAreEmpty_doesNotInterpolateIt() throws Exception {
    DocumentContext response = subject
        .interpolateCredHubReferences("{}", mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse("{}")));
  }

  @Test
  public void interpolateCredHubReferences_whenServicePropertiesAreNotArrays_doesNotInterpolateIt() throws Exception {
    String inputJsonString = "{"
        + "  \"pp-config-server\": {"
        + "    \"credentials\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }"
        + "}";
    DocumentContext response = subject
        .interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
            eventAuditRecordParameters);

    assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
  }

  @Test(expected = InvalidJsonException.class)
  public void interpolateCredHubReferences_whenInputIsNotJson_throwsAnException() throws Exception {
    String inputJsonString = "</xml?>";

    subject.interpolateCredHubReferences(inputJsonString, mock(CredentialDataService.class),
        eventAuditRecordParameters);
  }

  private void setupValidRequest() throws Exception {
    String inputJson = "{"
        + "  \"pp-config-server\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred1))\""
        + "      },"
        + "      \"label\": \"pp-config-server\""
        + "    },"
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred2))\""
        + "      }"
        + "    }"
        + "  ],"
        + "  \"pp-something-else\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred3))\""
        + "      },"
        + "      \"something\": [\"pp-config-server\"]"
        + "    }"
        + "  ]"
        + "}";

    JsonCredential jsonCredential = mock(JsonCredential.class);
    when(jsonCredential.getName()).thenReturn("/cred1");
    doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonCredential).getValue();

    JsonCredential jsonCredential1 = mock(JsonCredential.class);
    when(jsonCredential1.getName()).thenReturn("/cred2");
    doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonCredential1).getValue();

    JsonCredential jsonCredential2 = mock(JsonCredential.class);
    when(jsonCredential2.getName()).thenReturn("/cred3");
    Map<String, String> jsonCredetials = Maps.newHashMap("secret3-1", "secret3-1-value");
    jsonCredetials.put("secret3-2", "secret3-2-value");
    doReturn(jsonCredetials).when(jsonCredential2).getValue();

    CredentialDataService mockCredentialDataService = mock(CredentialDataService.class);

    doReturn(
        jsonCredential
    ).when(mockCredentialDataService).findMostRecent("/cred1");

    doReturn(
        jsonCredential1
    ).when(mockCredentialDataService).findMostRecent("/cred2");

    doReturn(
        jsonCredential2
    ).when(mockCredentialDataService).findMostRecent("/cred3");

    response = subject
        .interpolateCredHubReferences(
            inputJson,
            mockCredentialDataService,
            eventAuditRecordParameters
        );
  }
}

