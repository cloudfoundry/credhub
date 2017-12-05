package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_UPDATE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.cloudfoundry.credhub.util.CertificateReader.getCertificate;
import static org.cloudfoundry.credhub.util.CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = {CredentialManagerApp.class})
@Transactional
public class PermissionAndCredentialTest {

  public static final String MTLS_APP_GUID = "mtls-app:app1-guid";
  @Autowired
  private WebApplicationContext webApplicationContext;
  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;
  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;
  private String requestBody;

  @Before
  public void setUp() throws Exception {
    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void put_withPasswordGrant() throws Exception {
    requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\"\n" +
        "  ,\"value\":\"ORIGINAL-VALUE\"\n" +
        "}";

    ResultActions result = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));
    assertAclSuccessfullyCreatedAndAudited(
        result,
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
  }

  @Test
  public void post_withPasswordGrant() throws Exception {
    requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\"\n" +
        "}";

    ResultActions result = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));
    assertAclSuccessfullyCreatedAndAudited(
        result,
        UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
  }

  @Test
  public void put_withClientCredential() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\",\n" +
        "  \"value\":\"ORIGINAL-VALUE\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertAclSuccessfullyCreatedAndAudited(result, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void post_withClientCredential() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertAclSuccessfullyCreatedAndAudited(result, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void put_withMtls() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\",\n" +
        "  \"value\":\"ORIGINAL-VALUE\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(put("/api/v1/data")
        .with(x509(getCertificate(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertAclSuccessfullyCreatedAndAudited(
        result,
        "mtls-app:a12345e5-b2b0-4648-a0d0-772d3d399dcb",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
  }

  @Test
  public void post_withMtls() throws Exception {
    String requestBody = "{\n" +
        "  \"type\":\"password\",\n" +
        "  \"name\":\"/test-password\"\n" +
        "}";

    final ResultActions result = mockMvc.perform(post("/api/v1/data")
        .with(x509(getCertificate(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertAclSuccessfullyCreatedAndAudited(
        result,
        "mtls-app:a12345e5-b2b0-4648-a0d0-772d3d399dcb",
        UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
  }

  @Test
  public void put_withClientCredentialAndAnAce() throws Exception {
    // language=JSON
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"value\":\"ORIGINAL-VALUE\",\n"
        + "  \"additional_permissions\": [{\n"
        + "  \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "  \"operations\": [\"read\"]\n"
        + "  }]\n"
        + "}";

    final ResultActions result = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCreatorAndExtraAclSuccessfullyCreatedAndAudited(result, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void post_withClientCredentialAndAnAce() throws Exception {
    // language=JSON
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "    \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "    \"operations\": [\"read\"]\n"
        + "  }]\n"
        + "}";

    final ResultActions result = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody));

    assertCreatorAndExtraAclSuccessfullyCreatedAndAudited(result, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void put_withExistingCredentialAndAnAce_andOverwriteSetToTrue() throws Exception {
    createExistingCredential();

    // language=JSON
    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"value\":\"ORIGINAL-VALUE\", \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"uaa-client:credhub_test\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces));

    assertAclUpdatedAndAudited(response, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void post_withExistingCredentialAndAnAce_andOverwriteSetToTrue() throws Exception {
    createExistingCredential();

    // language=JSON
    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"uaa-client:credhub_test\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces))
        .andDo(print());

    assertAclUpdatedAndAudited(response, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
  }

  @Test
  public void put_withExistingCredentialAndAnAce_andOverwriteSetToFalse() throws Exception {
    createExistingCredential();

    // language=JSON
    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":false, \n"
        + "  \"value\":\"ORIGINAL-VALUE\", \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"uaa-client:credhub_test\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces));

    assertAclNotUpdatedButStillAudited(response);
  }

  @Test
  public void post_withExistingCredentialAndAnAce_andOverwriteSetToFalse() throws Exception {
    createExistingCredential();

    // language=JSON
    String requestBodyWithNewAces = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":false, \n"
        + "  \"additional_permissions\": [{\n"
        + "      \"actor\": \"" + MTLS_APP_GUID + "\",\n"
        + "      \"operations\": [\"write\"]},\n"
        + "    { \"actor\": \"uaa-client:credhub_test\",\n"
        + "      \"operations\": [\"read\", \"write\", \"delete\"]}\n"
        + "  ]\n"
        + "}";

    ResultActions response = mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBodyWithNewAces));

    assertAclNotUpdatedButStillAudited(response);
  }

  @Test
  public void put_whenRequestingInvalidPermissionOperation_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"type\":\"password\",\n"
            + "  \"name\":\"/test-password\",\n"
            + "  \"overwrite\":true, \n"
            + "  \"value\":\"ORIGINAL-VALUE\", \n"
            + "  \"additional_permissions\": [{\n"
            + "    \"actor\": \"" + MTLS_APP_GUID + "\",\n"
            + "    \"operations\": [\"unicorn\"]\n"
            + "  }]\n"
            + "}");

    this.mockMvc.perform(put).andExpect(status().is4xxClientError())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(
            "The provided operation is not supported."
                + " Valid values include read, write, delete, read_acl, and write_acl."));
  }

  @Test
  public void post_whenRequestingInvalidPermissionOperation_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\n"
            + "  \"type\":\"password\",\n"
            + "  \"name\":\"/test-password\",\n"
            + "  \"overwrite\":true, \n"
            + "  \"additional_permissions\": [{\n"
            + "    \"actor\": \"" + MTLS_APP_GUID + "\",\n"
            + "    \"operations\": [\"unicorn\"]\n"
            + "  }]\n"
            + "}");

    this.mockMvc.perform(post).andExpect(status().is4xxClientError())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(
            "The provided operation is not supported."
                + " Valid values include read, write, delete, read_acl, and write_acl."));
  }

  private void createExistingCredential() throws Exception {
    String requestBody = "{\n"
        + "  \"type\":\"password\",\n"
        + "  \"name\":\"/test-password\",\n"
        + "  \"overwrite\":true, \n"
        + "  \"additional_permissions\": [{\n"
        + "    \"actor\": \"uaa-client:credhub_test\",\n"
        + "    \"operations\": [\"read\", \"write\"]\n"
        + "  }]"
        + "}";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(requestBody))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type", equalTo("password")));
  }

  private void assertAclSuccessfullyCreatedAndAudited(ResultActions result, String actor, String token)
      throws Exception {
    succeeds(result);

    auditsTheRequest(actor);
    hasCreatorAcl(token, actor);
  }

  private void assertCreatorAndExtraAclSuccessfullyCreatedAndAudited(ResultActions result, String actor, String token)
      throws Exception {
    succeeds(result);

    auditsTheRequestWithExtraActor(actor);
    hasCreatorAndOtherAcl(token, actor);
  }

  private void assertAclUpdatedAndAudited(ResultActions result, String token)
      throws Exception {
    succeeds(result);

    auditsTheRequestWithNewPermissions();
    hasEditedAcl(token);
  }


  private void assertAclNotUpdatedButStillAudited(ResultActions response) throws Exception {
    succeeds(response);

    auditsTheRequestWithNoNewPermissions();
    hasUnchangedAcl();
  }

  private void hasUnchangedAcl() throws Exception {
    MvcResult result = mockMvc
        .perform(get("/api/v1/permissions?credential_name=" + "/test-password")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
                asList(READ, WRITE)))));
  }

  private void auditsTheRequestWithNoNewPermissions() throws Exception {
    List<EventAuditRecordParameters> auditRecordParameters = newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/test-password")
    );
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/data",
        200,
        auditRecordParameters
    );
  }

  private void hasEditedAcl(String token) throws Exception {
    MvcResult result = mockMvc
        .perform(get("/api/v1/permissions?credential_name=/test-password")
            .header("Authorization", "Bearer " + token))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry(MTLS_APP_GUID,
                asList(WRITE))),
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
                asList(READ, WRITE, DELETE)))));
  }

  private void auditsTheRequestWithNewPermissions() {
    List<EventAuditRecordParameters> auditRecordParameters = newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_UPDATE, "/test-password"),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE, MTLS_APP_GUID),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", DELETE, UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID)
    );
    auditingHelper.verifyAuditing(
        UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID,
        "/api/v1/data",
        200,
        auditRecordParameters
    );
  }

  private PermissionsView getAcl(String token) throws Exception {
    MvcResult result = mockMvc
        .perform(get("/api/v1/permissions?credential_name=/test-password")
            .header("Authorization", "Bearer " + token))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);
    assertThat(acl.getCredentialName(), equalTo("/test-password"));
    return acl;
  }

  private void hasCreatorAcl(String token, String actor) throws Exception {
    assertThat(getAcl(token).getPermissions(), Matchers.contains(samePropertyValuesAs(new PermissionEntry(actor,
        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
  }

  private void hasCreatorAndOtherAcl(String token, String actor) throws Exception {
    assertThat(getAcl(token).getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(actor,
            asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry(MTLS_APP_GUID, asList(READ)))));
  }

  private void auditsTheRequest(String actor) {
    List<EventAuditRecordParameters> auditRecordParameters = newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_UPDATE, "/test-password"),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", DELETE, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ_ACL, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE_ACL, actor)
    );

    auditingHelper.verifyAuditing(
        actor,
        "/api/v1/data",
        200,
        auditRecordParameters
    );
  }

  private void auditsTheRequestWithExtraActor(String actor) {
    List<EventAuditRecordParameters> auditRecordParameters = newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_UPDATE, "/test-password"),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ, MTLS_APP_GUID),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", DELETE, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", READ_ACL, actor),
        new EventAuditRecordParameters(ACL_UPDATE, "/test-password", WRITE_ACL, actor)
    );

    auditingHelper.verifyAuditing(
        actor,
        "/api/v1/data",
        200,
        auditRecordParameters
    );
  }

  private void succeeds(ResultActions result) throws Exception {
    result
        .andExpect(status().isOk())
        .andDo(print())
        .andExpect(jsonPath("$.type", equalTo("password")));
  }
}
