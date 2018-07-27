package org.cloudfoundry.credhub.integration;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.cloudfoundry.credhub.util.AuthConstants.*;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
//Not a Transactional test since manual cleanup plays more nicely with threads
public class NoOverwriteTest {
  private static final String CREDENTIAL_NAME = "TEST-SECRET";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private Flyway flyway;

  @Autowired
  private EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  private MockMvc mockMvc;
  private List<EncryptionKeyCanary> canaries;

  @Before
  public void beforeEach() throws Exception {
    canaries = encryptionKeyCanaryRepository.findAll();

    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @After
  public void afterEach() {
    flyway.clean();
    flyway.setTarget(MigrationVersion.LATEST);
    flyway.migrate();

    encryptionKeyCanaryRepository.saveAll(canaries);
    encryptionKeyCanaryRepository.flush();
  }

  @Test
  public void whenMultipleThreadsGenerateCredentialWithSameNameAndConverge_AndSameParameters_itShouldNotOverwrite() throws Exception {
    // We need to set the parameters so that we can determine which actor's request won,
    // even with authorization enforcement disabled.
    ResultActions[] responses = runRequestsConcurrently(CREDENTIAL_NAME,
        "\"parameters\":{\"exclude_lower\":true,\"exclude_upper\":true}",
        "\"parameters\":{\"exclude_lower\":true,\"exclude_upper\":true}",
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
        .perform(get("/api/v1/data?name=/" + CREDENTIAL_NAME)
            .header("Authorization", "Bearer " + USER_A_TOKEN))
        .andDo(print())
        .andReturn().getResponse();

    JSONObject jsonObj = new JSONObject(response1.getContentAsString());
    JSONArray jsonArray = jsonObj.getJSONArray("data");
    assertThat(jsonArray.length(), is(equalTo(1)));
  }

  private ResultActions[] runRequestsConcurrently(
      String credentialName,
      String additionalJsonPayload1,
      String additionalJsonPayload2,
      Supplier<MockHttpServletRequestBuilder> requestBuilderProvider) throws InterruptedException {
    ResultActions[] responses = new ResultActions[2];

    Thread thread1 = new Thread("thread1") {
      @Override
      public void run() {
        final MockHttpServletRequestBuilder requestBuilder = requestBuilderProvider.get()
            .header("Authorization", "Bearer " + USER_A_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(
                // language=JSON
                "{"
                    + "\"type\":\"password\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + credentialName + "\","
                    + additionalJsonPayload1
                    + "\n" +
                    "}");

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
            .header("Authorization", "Bearer " + USER_B_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(
                // language=JSON
                "{"
                    + "\"type\":\"password\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + credentialName + "\", "
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
