package io.pivotal.security.integration;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NoOverwriteTest {

  private static final String CREDENTIAL_NAME = "TEST-SECRET";
  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);
  @Autowired
  WebApplicationContext webApplicationContext;
  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;
  private ResultActions[] responses;
  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      encryptionKeyCanaryMapper.mapUuidsToKeys();
      fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("when multiple threads attempt to create a credential with the same name with no-overwrite", () -> {
      beforeEach(() -> {
        runRequestsConcurrently(
            ",\"value\":\"thread1\"",
            ",\"value\":\"thread2\"",
            () -> put("/api/v1/data"));
      });

      it("should not overwrite the value and the ACEs", () -> {
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

        MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + CREDENTIAL_NAME)
            .header("Authorization", "Bearer " + tokenForWinningActor))
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn();
        String content = result.getResponse().getContentAsString();
        AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);

        assertThat(acl.getAccessControlList(), containsInAnyOrder(
            samePropertyValuesAs(
                new AccessControlEntry(winningActor,
                    asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
            samePropertyValuesAs(
                new AccessControlEntry("uaa-client:a-different-actor", asList(READ)))
        ));
      });
    });

    describe("when multiple threads attempt to generate a credential with the same name with no-overwrite", () -> {
      beforeEach(() -> {
        // We need to set the parameters so that we can determine which actor's request won,
        // even with authorization enforcement disabled.
        runRequestsConcurrently(
            ",\"parameters\":{\"exclude_lower\":true,\"exclude_upper\":true}",
            ",\"parameters\":{\"exclude_number\":true}",
            () -> post("/api/v1/data"));
      });

      it("should not overwrite the value and the ACEs", () -> {
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
            .perform(get("/api/v1/acls?credential_name=" + CREDENTIAL_NAME)
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
            .andDo(print())
            .andReturn().getResponse();

        MockHttpServletResponse response2 = mockMvc
            .perform(get("/api/v1/acls?credential_name=" + CREDENTIAL_NAME)
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

        AccessControlListResponse acl = JsonHelper.deserialize(winningResponse, AccessControlListResponse.class);
        assertThat(acl.getAccessControlList(), containsInAnyOrder(
        samePropertyValuesAs(
            new AccessControlEntry(winningActor,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new AccessControlEntry("uaa-client:a-different-actor", singletonList(READ)))
        ));
      });
    });
  }

  private void runRequestsConcurrently(
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
                    + "\"name\":\"" + CREDENTIAL_NAME + "\","
                    + "\"access_control_entries\":[{"
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
                    + "\"name\":\"" + CREDENTIAL_NAME + "\", "
                    + "\"access_control_entries\":[{"
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
  }
}
