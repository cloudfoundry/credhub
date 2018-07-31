package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.credhub.helper.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test","unit-test-permissions"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialFindTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  private final String credentialName = "/my-namespace/subTree/credential-name";

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void findCredentials_byNameLike_whenSearchTermContainsNoSlash_returnsCredentialMetadata() throws Exception {
    ResultActions response = findCredentialsByNameLike();

    response.andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byPath_returnsCredentialMetaData() throws Exception {
    String substring = credentialName.substring(0, credentialName.lastIndexOf("/"));
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder getResponse = get("/api/v1/data?path=" + substring)
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(getResponse)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byPath_shouldOnlyFindPathsThatBeginWithSpecifiedSubstringCaseInsensitively() throws Exception {
    final String path = "namespace";

    assertTrue(credentialName.contains(path));

    MockHttpServletRequestBuilder request = get("/api/v1/data?path=" + path.toUpperCase())
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_shouldReturnAllChildrenPrefixedWithThePathCaseInsensitively() throws Exception {
    final String path = "/my-namespace";
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    assertTrue(credentialName.startsWith(path));

    final MockHttpServletRequestBuilder getRequest = get("/api/v1/data?path=" + path.toUpperCase())
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(getRequest).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(1)));
  }

  @Test
  public void findCredentials_byPath_shouldNotReturnCredentialsThatMatchThePathIncompletely() throws Exception {
    final String path = "/my-namespace/subTr";

    assertTrue(credentialName.startsWith(path));

    final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(get).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_savesTheAuditLog() throws Exception {
    String substring = credentialName.substring(0, credentialName.lastIndexOf("/"));
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=" + substring)
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(request);
  }

  @Test
  public void findCredentials_byPath_returnsNoCredentialsIfUserDoesNotHaveReadAccess() throws Exception {
    generateCredentials();

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/")
        .header("Authorization", "Bearer " + USER_A_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(0)));
  }

  @Test
  public void findCredentials_byPath_returnsAllCredentialsWhenUserHasAllPermissions() throws Exception {
    generateCredentials();

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/")
        .header("Authorization", "Bearer " + USER_A_TOKEN)
        .accept(APPLICATION_JSON);

    setPermissions("/*", PermissionOperation.READ);

    mockMvc.perform(request).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(5)));
  }

  @Test
  public void findCredentials_byPath_returnsSubsetWithFullPermissionPath() throws Exception {
    String credentialName = "/other_path/credentialC";
    generateCredentials();

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/")
        .header("Authorization", "Bearer " + USER_A_TOKEN)
        .accept(APPLICATION_JSON);

    setPermissions(credentialName, PermissionOperation.READ);

    mockMvc.perform(request).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(1)))
        .andExpect(jsonPath("$.credentials[0].name").value(credentialName));
  }

  @Test
  public void findCredentials_byPath_returnsSubsetWithAsteriskInPermissionPath() throws Exception {
    generateCredentials();

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/")
        .header("Authorization", "Bearer " + USER_A_TOKEN)
        .accept(APPLICATION_JSON);

    setPermissions("/path/to/*", PermissionOperation.READ);

    mockMvc.perform(request).andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.credentials", hasSize(2)))
        .andExpect(jsonPath("$.credentials[1].name").value("/path/to/credentialA"))
        .andExpect(jsonPath("$.credentials[0].name").value("/path/to/credentialB"));
  }

  private void generateCredentials() throws Exception{
    List<String> names = Arrays.asList(new String[] {"/path/to/credentialA", "/path/something",
        "/path/to/credentialB", "/other_path/credentialC", "/another/credentialC"});

    for(String name : names){
      generatePassword(mockMvc, name, true, 20, ALL_PERMISSIONS_TOKEN);
    }
  }

  private void setPermissions(String path, PermissionOperation operation) throws Exception{
    MockHttpServletRequestBuilder addPermissionRequest = post("/api/v2/permissions")
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
            + "  \"path\": \"" + path + "\",\n"
            + "  \"operations\": [\"" + operation.getOperation() + "\"]\n"
            + "}");

    String content = mockMvc.perform(addPermissionRequest).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
    PermissionsV2View returnValue = JsonTestHelper.deserialize(content, PermissionsV2View.class);
    assertThat(returnValue.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(returnValue.getPath(), equalTo(path));
    assertThat(returnValue.getOperations(), equalTo(Collections.singletonList(operation)));

    assertThat(returnValue.getUuid(), notNullValue());
  }

  private ResultActions findCredentialsByNameLike() throws Exception {
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);
    String substring = credentialName.substring(4).toUpperCase();

    final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + substring)
        .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    return mockMvc.perform(get);
  }
}
