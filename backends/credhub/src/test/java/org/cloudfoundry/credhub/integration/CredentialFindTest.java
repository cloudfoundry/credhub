package org.cloudfoundry.credhub.integration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generatePassword;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
@SuppressFBWarnings(
  value = "SS_SHOULD_BE_STATIC",
  justification = "Test files generally don't need static fields."
)
public class CredentialFindTest {

  private final String credentialName = "/my-namespace/subTree/credential-name";
  @Autowired
  private WebApplicationContext webApplicationContext;
  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void findCredentials_byNameLike_whenSearchTermContainsNoSlash_returnsCredentialMetadata() throws Exception {
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);
    final ResultActions response = findCredentialsByNameLike(credentialName.substring(4).toUpperCase(),
      ALL_PERMISSIONS_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byNameLike_returnsNoCredentialsIfUserDoesNotHaveReadAccess() throws Exception {
    generateCredentials();
    final ResultActions response = findCredentialsByNameLike("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byNameLike_returnsAllCredentialsWhenUserHasAllPermissions() throws Exception {
    generateCredentials();

    setPermissions("/*", PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByNameLike("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(6)));
  }

  @Test
  public void findCredentials_byNameLike_returnsSubsetWithFullPermissionPath() throws Exception {
    final String credentialName = "/other_path/credentialC";
    generateCredentials();

    setPermissions(credentialName, PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByNameLike("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byNameLike_withUnderscore_escapesWildcard() throws Exception {
    final String credentialName = "/other_path/credentialC";
    final String otherCredentialName = "/other/path/credentialC";
    generateCredentials();

    setPermissions(credentialName, PermissionOperation.READ, USER_A_ACTOR_ID);
    setPermissions(otherCredentialName, PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByNameLike("other_path", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value(credentialName));

  }

  @Test
  public void findCredentials_byPath_returnsCredentialMetaData() throws Exception {
    final String substring = credentialName.substring(0, credentialName.lastIndexOf("/"));
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    final ResultActions response = findCredentialsByPath(substring, ALL_PERMISSIONS_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byPath_shouldOnlyFindPathsThatBeginWithSpecifiedSubstringCaseInsensitively()
    throws Exception {
    final String path = "namespace";

    assertTrue(credentialName.contains(path));

    final ResultActions response = findCredentialsByPath(path.toUpperCase(), ALL_PERMISSIONS_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_shouldReturnAllChildrenPrefixedWithThePathCaseInsensitively() throws Exception {
    final String path = "/my-namespace";
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    assertTrue(credentialName.startsWith(path));

    final ResultActions response = findCredentialsByPath(path.toUpperCase(), ALL_PERMISSIONS_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)));
  }

  @Test
  public void findCredentials_byPath_shouldNotReturnCredentialsThatMatchThePathIncompletely() throws Exception {
    final String path = "/my-namespace/subTr";

    assertTrue(credentialName.startsWith(path));

    final ResultActions response = findCredentialsByPath(path, ALL_PERMISSIONS_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_returnsNoCredentialsIfUserDoesNotHaveReadAccess() throws Exception {
    generateCredentials();

    final ResultActions response = findCredentialsByPath("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_returnsAllCredentialsWhenUserHasAllPermissions() throws Exception {
    generateCredentials();

    setPermissions("/*", PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByPath("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(6)));
  }

  @Test
  public void findCredentials_byPath_returnsSubsetWithFullPermissionPath() throws Exception {
    final String credentialName = "/other_path/credentialC";
    generateCredentials();

    setPermissions(credentialName, PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByPath("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byPath_returnsSubsetWithAsteriskInPermissionPath() throws Exception {
    generateCredentials();

    setPermissions("/path/to/*", PermissionOperation.READ, USER_A_ACTOR_ID);

    final ResultActions response = findCredentialsByPath("/", USER_A_TOKEN);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(2)))
      .andExpect(jsonPath("$.credentials[1].name").value("/path/to/credentialA"))
      .andExpect(jsonPath("$.credentials[0].name").value("/path/to/credentialB"));
  }

  @Test
  public void findCredentialsByPath_withExpiryDate() throws Exception {

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"notExpiring\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 32 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"willExpire\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 29 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    final String expiresWithinDays = "30";
    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/&expires-within-days=" + expiresWithinDays)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .content("expires-within-days:30")
      .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value("/willExpire"));

  }

  @Test
  public void findCertificatesByPath_withExpiryDate_andWithUnderscore_escapesWildcard() throws Exception {

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"some_path/test\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 30 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"some/path/test\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 30 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/some_path&expires-within-days=45")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .content("expires-within-days:45")
      .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value("/some_path/test"));

  }

  @Test
  public void findCredentialsByPath_withExpiryDate_andLatestVersionIsNotExpiring_returnsNothing() throws Exception {

    this.mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            //language=JSON
            .content("{\n"
                    + "  \"name\" : \"sample-certificate\",\n"
                    + "  \"type\" : \"certificate\",\n"
                    + "  \"parameters\" : {\n"
                    + "    \"common_name\" : \"some-common-name\",\n"
                    + "    \"is_ca\" : true,\n"
                    + "    \"self_sign\" : true,\n"
                    + "    \"duration\" : 5 \n"
                    + "  }\n"
                    + "}"))
            .andDo(print())
            .andExpect(status().isOk());

    this.mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            //language=JSON
            .content("{\n"
                    + "  \"name\" : \"sample-certificate\",\n"
                    + "  \"type\" : \"certificate\",\n"
                    + "  \"parameters\" : {\n"
                    + "    \"common_name\" : \"some-common-name\",\n"
                    + "    \"is_ca\" : true,\n"
                    + "    \"self_sign\" : true,\n"
                    + "    \"duration\" : 365 \n"
                    + "  }\n"
                    + "}"))
            .andDo(print())
            .andExpect(status().isOk());

    final String expiresWithinDays = "30";
    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/&expires-within-days=" + expiresWithinDays)
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .content("expires-within-days:30")
            .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.credentials", hasSize(0)));

  }

  @Test
  public void findCredentialsByPath_withExpiryDate_andLatestVersionIsExpiring_returnsTheLatestVersion() throws Exception {

    this.mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            //language=JSON
            .content("{\n"
                    + "  \"name\" : \"sample-certificate\",\n"
                    + "  \"type\" : \"certificate\",\n"
                    + "  \"parameters\" : {\n"
                    + "    \"common_name\" : \"some-common-name\",\n"
                    + "    \"is_ca\" : true,\n"
                    + "    \"self_sign\" : true,\n"
                    + "    \"duration\" : 5 \n"
                    + "  }\n"
                    + "}"))
            .andDo(print())
            .andExpect(status().isOk());

    this.mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            //language=JSON
            .content("{\n"
                    + "  \"name\" : \"sample-certificate\",\n"
                    + "  \"type\" : \"certificate\",\n"
                    + "  \"parameters\" : {\n"
                    + "    \"common_name\" : \"some-common-name\",\n"
                    + "    \"is_ca\" : true,\n"
                    + "    \"self_sign\" : true,\n"
                    + "    \"duration\" : 10 \n"
                    + "  }\n"
                    + "}"))
            .andDo(print())
            .andExpect(status().isOk());

    final String expiresWithinDays = "30";
    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/&expires-within-days=" + expiresWithinDays)
            .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
            .content("expires-within-days:30")
            .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.credentials", hasSize(1)))
            .andExpect(jsonPath("$.credentials[0].name").value("/sample-certificate"));

  }

  @Test
  public void findCredentialsByName_withExpiryDate() throws Exception {

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"notExpiring\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 32 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    this.mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      //language=JSON
      .content("{\n"
        + "  \"name\" : \"willExpire\",\n"
        + "  \"type\" : \"certificate\",\n"
        + "  \"parameters\" : {\n"
        + "    \"common_name\" : \"federation\",\n"
        + "    \"is_ca\" : true,\n"
        + "    \"self_sign\" : true,\n"
        + "    \"duration\" : 29 \n"
        + "  }\n"
        + "}"))
      .andDo(print())
      .andExpect(status().isOk());

    final String expiresWithinDays = "30";
    final MockHttpServletRequestBuilder request = get(
      "/api/v1/data?name-like=ex&expires-within-days=" + expiresWithinDays)
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .content("expires-within-days:30")
      .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(1)))
      .andExpect(jsonPath("$.credentials[0].name").value("/willExpire"));

  }

  private void generateCredentials() throws Exception {
    final List<String> names = Arrays.asList(new String[]{"/path/to/credentialA", "/path/something",
      "/path/to/credentialB", "/other_path/credentialC", "/other/path/credentialC", "/another/credentialC"});

    for (final String name : names) {
      generatePassword(mockMvc, name, true, 20, ALL_PERMISSIONS_TOKEN);
    }
  }

  private void setPermissions(final String path, final PermissionOperation operation, final String actorID) throws Exception {
    final MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"actor\": \"" + actorID + "\",\n"
        + "  \"path\": \"" + path + "\",\n"
        + "  \"operations\": [\"" + operation.getOperation() + "\"]\n"
        + "}");

    final String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse()
      .getContentAsString();
    final PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(path));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(operation)));

    assertThat(returnValue.getUuid(), notNullValue());
  }

  private ResultActions findCredentialsByNameLike(final String pattern, final String permissionsToken) throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + pattern)
      .header("Authorization", "Bearer " + permissionsToken)
      .accept(APPLICATION_JSON);

    return mockMvc.perform(get);
  }

  private ResultActions findCredentialsByPath(final String path, final String permissionsToken) throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
      .header("Authorization", "Bearer " + permissionsToken)
      .accept(APPLICATION_JSON);

    return mockMvc.perform(get);
  }
}
