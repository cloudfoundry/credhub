package org.cloudfoundry.credhub.handlers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.interpolation.DefaultInterpolationHandler;
import org.cloudfoundry.credhub.services.DefaultCredentialService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.internal.verification.VerificationModeFactory;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultInterpolationHandlerTest {
  private static final String UUID_STRING = UUID.randomUUID().toString();
  private static final String USER = "darth-sirius";
  private static final String CREDENTIAL_NAME = "/test/credential";

  private DefaultInterpolationHandler subjectWithAclsEnabled;
  private DefaultInterpolationHandler subjectWithAclsDisabled;
  private Map<String, Object> response;
  private DefaultCredentialService credentialService;
  private CEFAuditRecord auditRecord;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;

  @Before
  public void beforeEach() {
    credentialService = mock(DefaultCredentialService.class);
    auditRecord = mock(CEFAuditRecord.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    UserContext userContext = mock(UserContext.class);
    userContextHolder = mock(UserContextHolder.class);
    when(userContext.getActor()).thenReturn(USER);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    subjectWithAclsEnabled = new DefaultInterpolationHandler(
      credentialService,
      auditRecord,
      permissionCheckingService,
      userContextHolder,
      true);

    subjectWithAclsDisabled = new DefaultInterpolationHandler(
      credentialService,
      auditRecord,
      permissionCheckingService,
      userContextHolder,
      false);
  }

  @Test
  public void interpolateCredHubReferences_whenUserHasPermission_andAclsAreEnabled_replacesTheCredHubRefWithSomethingElse() {
    setupValidRequest();

    final ArrayList firstService = (ArrayList) response.get("pp-config-server");
    final ArrayList secondService = (ArrayList) response.get("pp-something-else");

    final JsonNode firstCredentialsBlock = (JsonNode) ((Map<String, Object>) firstService.get(0))
      .get("credentials");
    final JsonNode secondCredentialsBlock = (JsonNode) ((Map<String, Object>) firstService.get(1))
      .get("credentials");

    final JsonNode secondServiceCredentials = (JsonNode) ((Map<String, Object>) secondService.get(0))
      .get("credentials");

    assertThat(firstCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(firstCredentialsBlock.size(), equalTo(1));
    assertThat(firstCredentialsBlock.get("secret1").toString(), equalTo("\"secret1-value\""));

    assertThat(secondCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(secondCredentialsBlock.size(), equalTo(1));
    assertThat(secondCredentialsBlock.get("secret2").toString(), equalTo("\"secret2-value\""));

    assertThat(secondServiceCredentials.get("credhub-ref"), nullValue());
    assertThat(secondServiceCredentials.size(), equalTo(2));
    assertThat(secondServiceCredentials.get("secret3-1").toString(), equalTo("\"secret3-1-value\""));
    assertThat(secondServiceCredentials.get("secret3-2").toString(), equalTo("\"secret3-2-value\""));
  }

  @Test
  public void interpolateCredHub_addsToTheAuditRecord() {
    setupValidRequest();

    verify(auditRecord, times(3)).addResource(any(Credential.class));
    verify(auditRecord, times(3)).addVersion(any(CredentialVersion.class));

  }

  @Test
  public void interpolateCredHubReferences_whenAReferencedCredentialIsNotJsonType_itThrowsAnException() {
    //lang=JSON
    final String inputJson = "{"
      + "  \"pp-config-server\": ["
      + "    {"
      + "      \"credentials\": {"
      + "        \"credhub-ref\": \"((/password_cred))\""
      + "      },"
      + "      \"label\": \"pp-config-server\""
      + "    }"
      + "  ]"
      + "}";

    final PasswordCredentialVersion passwordCredential = mock(PasswordCredentialVersion.class);
    when(passwordCredential.getName()).thenReturn("/password_cred");

    doReturn(singletonList(passwordCredential)).when(credentialService).findNByName("/password_cred", 1);

    when(permissionCheckingService.hasPermission(USER, "/password_cred", PermissionOperation.READ))
      .thenReturn(true);
    try {
      subjectWithAclsEnabled.interpolateCredHubReferences(deserialize(inputJson, Map.class));
    } catch (final ParameterizedValidationException exception) {
      assertThat(exception.getMessage(), equalTo(ErrorMessages.Interpolation.INVALID_TYPE));
    }
  }

  @Test
  public void interpolateCredHubReferences_whenTheServicePropertiesLackCredentials_doesNotInterpolateIt() {
    final Map<String, Object> inputJson = deserialize("{"
      + "  \"pp-config-server\": [{"
      + "    \"blah\": {"
      + "      \"credhub-ref\": \"((/cred1))\""
      + "     },"
      + "    \"label\": \"pp-config-server\""
      + "  }]"
      + "}", Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyHasNoRefs_doesNotInterpolateIt() {
    final Map<String, Object> inputJson = deserialize("{"
      + "  \"pp-config-server\": [{"
      + "    \"credentials\": {"
      + "      \"key\": \"((value))\""
      + "     },"
      + "    \"label\": \"pp-config-server\""
      + "  }]"
      + "}", Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyIsFormattedUnexpectedly_doesNotInterpolateIt() {
    final String inputJsonString = "{"
      + "  \"pp-config-server\": [{"
      + "    \"foo\": {"
      + "      \"credentials\": {"
      + "        \"credhub-ref\": \"((/cred1))\""
      + "       }"
      + "     },"
      + "    \"label\": \"pp-config-server\""
      + "  }]"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenThePropertiesAreNotAHash_doesNotInterpolateIt() {
    final String inputJsonString = "{"
      + "  \"pp-config-server\": [\"what is this?\"]"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsAreNotAHashInAnArray_doesNotInterpolateIt() {
    final String inputJsonString = "{"
      + "  \"pp-config-server\": [{"
      + "    \"credentials\": \"moose\","
      + "    \"label\": \"squirrel\""
      + "  }]"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenPropertiesAreEmpty_doesNotInterpolateIt() {
    final Map<String, Object> inputJson = deserialize("{}", Map.class);
    final Map<String, Object> response = subjectWithAclsEnabled
      .interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  @Test
  public void interpolateCredHubReferences_whenServicePropertiesAreNotArrays_doesNotInterpolateIt() {
    final String inputJsonString = "{"
      + "  \"pp-config-server\": {"
      + "    \"credentials\": {"
      + "      \"credhub-ref\": \"((/cred1))\""
      + "     },"
      + "    \"label\": \"pp-config-server\""
      + "  }"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    final Map response = subjectWithAclsEnabled.interpolateCredHubReferences(inputJson);

    assertThat(response, equalTo(inputJson));
  }

  private void setupValidRequest() {
    final String inputJsonString = "{"
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
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    final JsonCredentialVersion jsonCredential1 = mock(JsonCredentialVersion.class);
    when(jsonCredential1.getCredential()).thenReturn(mock(Credential.class));
    when(jsonCredential1.getName()).thenReturn("/cred1");
    final String credJson1 = "{\"secret1\":\"secret1-value\"}";
    final JsonNode jsonNode1;
    try {
      jsonNode1 = new ObjectMapper().readTree(credJson1);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    doReturn(jsonNode1).when(jsonCredential1).getValue();

    final JsonCredentialVersion jsonCredential2 = mock(JsonCredentialVersion.class);
    when(jsonCredential2.getCredential()).thenReturn(mock(Credential.class));
    when(jsonCredential2.getName()).thenReturn("/cred2");
    final String credJson2 = "{\"secret2\":\"secret2-value\"}";
    final JsonNode jsonNode2;
    try {
      jsonNode2 = new ObjectMapper().readTree(credJson2);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    doReturn(jsonNode2).when(jsonCredential2).getValue();

    final JsonCredentialVersion jsonCredential3 = mock(JsonCredentialVersion.class);
    when(jsonCredential3.getCredential()).thenReturn(mock(Credential.class));
    when(jsonCredential3.getName()).thenReturn("/cred3");
    final String credJson3 = "{\"secret3-1\":\"secret3-1-value\",\"secret3-2\":\"secret3-2-value\"}";
    final JsonNode jsonNode3;
    try {
      jsonNode3 = new ObjectMapper().readTree(credJson3);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }

    when(permissionCheckingService.hasPermission(USER, "/cred1", PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/cred2", PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/cred3", PermissionOperation.READ))
      .thenReturn(true);

    doReturn(jsonNode3).when(jsonCredential3).getValue();

    doReturn(singletonList(jsonCredential1)).when(credentialService).findNByName("/cred1", 1);

    doReturn(singletonList(jsonCredential2)).when(credentialService).findNByName("/cred2", 1);

    doReturn(singletonList(jsonCredential3)).when(credentialService).findNByName("/cred3", 1);

    response = subjectWithAclsEnabled.interpolateCredHubReferences(inputJson);
  }

  @Test
  public void interpolateCredhubReferences_whenUserLacksPermission_andAclsAreEnabled_throwsException() {
    final String inputJsonString = "{"
      + "  \"pp-config-server\": ["
      + "    {"
      + "      \"credentials\": {"
      + "        \"credhub-ref\": \"((/test/credential))\""
      + "      },"
      + "      \"label\": \"pp-config-server\""
      + "    },"
      + "    {"
      + "      \"credentials\": {"
      + "        \"credhub-ref\": \"((/cred2))\""
      + "      }"
      + "    }"
      + "  ]"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAclsEnabled.interpolateCredHubReferences(inputJson);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
        MatcherAssert.assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    } catch (final Exception e) {
        fail("expected EntryNotFoundException but got " + e.getClass().toString());
    }

    verify(permissionCheckingService, VerificationModeFactory.times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ);

  }

  @Test
  public void interpolateCredhubReferenceswhenAclsAreDisabled_interpolatesRefs() {

    final String inputJsonString = "{"
      + "  \"pp-config-server\": ["
      + "    {"
      + "      \"credentials\": {"
      + "        \"credhub-ref\": \"((/cred1))\""
      + "      },"
      + "      \"label\": \"pp-config-server\""
      + "    }"
      + "  ]"
      + "}";
    final Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    final JsonCredentialVersion jsonCredential1 = mock(JsonCredentialVersion.class);
    when(jsonCredential1.getCredential()).thenReturn(mock(Credential.class));
    when(jsonCredential1.getName()).thenReturn("/cred1");
    final String credJson1 = "{\"secret1\":\"secret1-value\"}";
    final JsonNode jsonNode1;
    try {
      jsonNode1 = new ObjectMapper().readTree(credJson1);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    doReturn(jsonNode1).when(jsonCredential1).getValue();

    doReturn(singletonList(jsonCredential1)).when(credentialService).findNByName("/cred1", 1);

    Map<String, Object> result = subjectWithAclsDisabled.interpolateCredHubReferences(inputJson);

    final ArrayList service = (ArrayList) result.get("pp-config-server");

    final JsonNode credentialsBlock = (JsonNode) ((Map<String, Object>) service.get(0))
      .get("credentials");

    verify(permissionCheckingService, times(0))
    .hasPermission(USER, "/cred1", PermissionOperation.READ);
    assertThat(credentialsBlock.size(), equalTo(1));
    assertThat(credentialsBlock.get("secret1").toString(), equalTo("\"secret1-value\""));




  }
}

