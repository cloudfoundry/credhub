package org.cloudfoundry.credhub.service;

import org.assertj.core.util.Maps;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.handler.InterpolationHandler;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserialize;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class InterpolationHandlerTest {

  private InterpolationHandler subject;
  private Map<String, Object> response;
  private PermissionedCredentialService credentialService;
  private CEFAuditRecord auditRecord;

  @Before
  public void beforeEach() {
    credentialService = mock(PermissionedCredentialService.class);
    auditRecord = mock(CEFAuditRecord.class);

    subject = new InterpolationHandler(credentialService, auditRecord);
  }

  @Test
  public void interpolateCredHubReferences_replacesTheCredHubRefWithSomethingElse() {
    setupValidRequest();

    final ArrayList firstService = (ArrayList) response.get("pp-config-server");
    final ArrayList secondService = (ArrayList) response.get("pp-something-else");

    Map<String, Object> firstCredentialsBlock = (Map<String, Object>) ((Map<String, Object>) firstService.get(0))
        .get("credentials");
    Map<String, Object> secondCredentialsBlock = (Map<String, Object>) ((Map<String, Object>) firstService.get(1))
        .get("credentials");

    Map<String, Object> secondServiceCredentials = (Map<String, Object>) ((Map<String, Object>) secondService.get(0))
        .get("credentials");

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
  public void interpolateCredHubReferences_whenAReferencedCredentialIsNotJsonType_itThrowsAnException() {
    //lang=JSON
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

    PasswordCredentialVersion passwordCredential = mock(PasswordCredentialVersion.class);
    when(passwordCredential.getName()).thenReturn("/password_cred");

    doReturn(singletonList(passwordCredential)).when(credentialService).findNByName("/password_cred", 1);

    try {
      subject.interpolateCredHubReferences(deserialize(inputJson, Map.class));
    } catch (ParameterizedValidationException exception) {
      assertThat(exception.getMessage(), equalTo("error.interpolation.invalid_type"));
    }
  }

  @Test
  public void interpolateCredHubReferences_whenTheServicePropertiesLackCredentials_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{"
        + "  \"pp-config-server\": [{"
        + "    \"blah\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyHasNoRefs_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": {"
        + "      \"key\": \"((value))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyIsFormattedUnexpectedly_doesNotInterpolateIt() {
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
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenThePropertiesAreNotAHash_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [\"what is this?\"]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsAreNotAHashInAnArray_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": \"moose\","
        + "    \"label\": \"squirrel\""
        + "  }]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenPropertiesAreEmpty_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenServicePropertiesAreNotArrays_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": {"
        + "    \"credentials\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map response = subject.interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  private void setupValidRequest() {
    String inputJsonString = "{"
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
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    JsonCredentialVersion jsonCredential = mock(JsonCredentialVersion.class);
    when(jsonCredential.getName()).thenReturn("/cred1");
    doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonCredential).getValue();

    JsonCredentialVersion jsonCredential1 = mock(JsonCredentialVersion.class);
    when(jsonCredential1.getName()).thenReturn("/cred2");
    doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonCredential1).getValue();

    JsonCredentialVersion jsonCredential2 = mock(JsonCredentialVersion.class);
    when(jsonCredential2.getName()).thenReturn("/cred3");
    Map<String, String> jsonCredetials = Maps.newHashMap("secret3-1", "secret3-1-value");
    jsonCredetials.put("secret3-2", "secret3-2-value");
    doReturn(jsonCredetials).when(jsonCredential2).getValue();

    doReturn(singletonList(jsonCredential)).when(credentialService).findNByName("/cred1", 1);

    doReturn(singletonList(jsonCredential1)).when(credentialService).findNByName("/cred2", 1);

    doReturn(singletonList(jsonCredential2)).when(credentialService).findNByName("/cred3", 1);

    response = subject.interpolateCredHubReferences(inputJson);
  }
}

