package io.pivotal.security.integration;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.PermissionsView;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.function.Supplier;

import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
//Not a Transactional test since manual cleanup plays more nicely with threads
public class NoOverwriteTest {

  private static final String CREDENTIAL_NAME = "TEST-SECRET";
  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private ResultActions[] responses;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }
  @After
  public void afterEach() throws Exception {
    mockMvc.perform(delete("/api/v1/data?name=" + CREDENTIAL_NAME).header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)).andDo(print());
  }


  @Test
  public void whenMultipleThreadsPutWithSameNameAndNoOverwrite_itShouldNotOverwrite()
      throws Exception {
    runRequestsConcurrently(CREDENTIAL_NAME,
        ",\"value\":\"thread1\"",
        ",\"value\":\"thread2\"",
        () -> put("/api/v1/data"));

    MvcResult result1 = responses[0]
        .andDo(print())
        .andReturn();
    final DocumentContext context1 = JsonPath.parse(result1.getResponse().getContentAsString());
    MvcResult result2 = responses[1]
        .andDo(print())
        .andReturn();
    final DocumentContext context2 = JsonPath.parse(result2.getResponse().getContentAsString());

    assertThat(context1.read("$.value"), equalTo(context2.read("$.value")));

    String winningValue = context1.read("$.value");

    String tokenForWinningActor = ImmutableMap
        .of("thread1", UAA_OAUTH2_PASSWORD_GRANT_TOKEN,
            "thread2", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .get(winningValue);
    String winningActor = ImmutableMap
        .of("thread1", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
            "thread2", "uaa-client:credhub_test")
        .get(winningValue);

    MvcResult result = mockMvc.perform(get("/api/v1/permissions?credential_name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + tokenForWinningActor))
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonHelper
        .deserialize(content, PermissionsView.class);

    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry(winningActor,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("uaa-client:a-different-actor", asList(READ)))
    ));

  }

  @Test
  public void whenMultipleThreadsGenerateCredentialWithSameNameAndNoOverwrite_itShouldNotOverwrite()
      throws Exception {
    // We need to set the parameters so that we can determine which actor's request won,
    // even with authorization enforcement disabled.
    runRequestsConcurrently(CREDENTIAL_NAME,
        ",\"parameters\":{\"exclude_lower\":true,\"exclude_upper\":true}",
        ",\"parameters\":{\"exclude_number\":true}",
        () -> post("/api/v1/data"));

    MvcResult result1 = responses[0]
        .andDo(print())
        .andReturn();
    final DocumentContext context1 = JsonPath.parse(result1.getResponse().getContentAsString());

    MvcResult result2 = responses[1]
        .andDo(print())
        .andReturn();
    final DocumentContext context2 = JsonPath.parse(result2.getResponse().getContentAsString());

    assertThat(context1.read("$.value"), equalTo(context2.read("$.value")));

    MockHttpServletResponse response1 = mockMvc
        .perform(get("/api/v1/permissions?credential_name=" + CREDENTIAL_NAME)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
        .andDo(print())
        .andReturn().getResponse();

    MockHttpServletResponse response2 = mockMvc
        .perform(get("/api/v1/permissions?credential_name=" + CREDENTIAL_NAME)
            .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN))
        .andDo(print())
        .andReturn().getResponse();

    String winningPassword = context1.read("$.value");
    String winningActor;
    String winningResponse;

    if (winningPassword.matches("\\d+")) {
      winningActor = "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d";
      winningResponse = response1.getContentAsString();
    } else {
      winningActor = "uaa-client:credhub_test";
      winningResponse = response2.getContentAsString();
    }

    PermissionsView acl = JsonHelper
        .deserialize(winningResponse, PermissionsView.class);
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry(winningActor,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("uaa-client:a-different-actor", singletonList(READ)))
    ));

  }

  private ResultActions[] runRequestsConcurrently(
      String credentialName,
      String additionalJsonPayload1,
      String additionalJsonPayload2,
      Supplier<MockHttpServletRequestBuilder> requestBuilderProvider) throws InterruptedException {
    responses = new ResultActions[2];

    Thread thread1 = new Thread("thread1") {
      @Override
      public void run() {
        final MockHttpServletRequestBuilder requestBuilder = requestBuilderProvider.get()
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(
                // language=JSON
                "{"
                    + "\"type\":\"password\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + credentialName + "\","
                    + "\"additional_permissions\":[{"
                    + "\"actor\":\"uaa-client:a-different-actor\","
                    + "\"operations\": [\"read\"]"
                    + "}]"
                    + additionalJsonPayload1
                    + "}");

        try {
          responses[0] = mockMvc.perform(requestBuilder);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    };

    Thread thread2 = new Thread("thread2") {
      @Override
      public void run() {
        final MockHttpServletRequestBuilder post = requestBuilderProvider.get()
            .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(
                // language=JSON
                "{"
                    + "\"type\":\"password\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + credentialName + "\", "
                    + "\"additional_permissions\":[{"
                    + "\"actor\":\"uaa-client:a-different-actor\","
                    + "\"operations\": [\"read\"]"
                    + "}]"
                    + additionalJsonPayload2
                    + "}");

        try {
          responses[1] = mockMvc.perform(post);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    };

    thread1.start();
    thread2.start();
    thread1.join();
    thread2.join();

    return responses;
  }
}
