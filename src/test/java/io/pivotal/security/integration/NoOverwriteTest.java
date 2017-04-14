package io.pivotal.security.integration;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import io.pivotal.security.view.PasswordView;
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

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.fit;
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

  private static final String SECRET_NAME = "TEST-SECRET";
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

    describe("when multiple threads attempt to create a secret with the same name with no-overwrite", () -> {
      beforeEach(() -> {
        runRequestsConcurrently(
            ",\"value\":\"uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\"",
            ",\"value\":\"uaa-client:credhub_test\"",
            () -> put("/api/v1/data"));
      });

      fit("should not overwrite the value and the ACEs", () -> {
        MvcResult result1 = responses[0]
            .andDo(print())
            .andReturn();
        PasswordView value1 = JsonHelper
            .deserialize(result1.getResponse().getContentAsString(), PasswordView.class);
        MvcResult result2 = responses[1]
            .andDo(print())
            .andReturn();
        PasswordView value2 = JsonHelper.deserialize(result2.getResponse().getContentAsString(), PasswordView.class);

        assertThat(value1.getValue(), equalTo(value2.getValue()));

        String winningActor = (String) value1.getValue();

        String tokenForWinningActor = ImmutableMap
            .of("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", UAA_OAUTH2_PASSWORD_GRANT_TOKEN,
                "uaa-client:credhub_test", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
            .get(winningActor);

        MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + SECRET_NAME)
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
                new AccessControlEntry("mtls:app:" + winningActor, asList(READ)))
        ));
      });
    });

    describe("when multiple threads attempt to generate a secret with the same name with no-overwrite", () -> {
      beforeEach(() -> {
        runRequestsConcurrently(
            "",
            "",
            () -> post("/api/v1/data"));
      });

      it("should not overwrite the value and the ACEs", () -> {
        MvcResult result1 = responses[0]
            .andDo(print())
            .andReturn();
        PasswordView password1 = JsonHelper
            .deserialize(result1.getResponse().getContentAsString(),PasswordView.class);
        MvcResult result2 = responses[1]
            .andDo(print())
            .andReturn();
        PasswordView password2 = JsonHelper.deserialize(result2.getResponse().getContentAsString(), PasswordView.class);

        assertThat(password1.getValue(), equalTo(password2.getValue()));

        MockHttpServletResponse response1 = mockMvc
            .perform(get("/api/v1/acls?credential_name=" + SECRET_NAME)
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
            .andDo(print())
            .andReturn().getResponse();

        MockHttpServletResponse response2 = mockMvc
            .perform(get("/api/v1/acls?credential_name=" + SECRET_NAME)
                .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN))
            .andDo(print())
            .andReturn().getResponse();

        testSuccessfulAclResponse(response1, response2, (String actor, String content) -> {
            AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
            samePropertyValuesAs(
                new AccessControlEntry(actor,
                    asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
            samePropertyValuesAs(
                new AccessControlEntry("mtls:app:" + actor, asList(READ)))
            ));
        });
      });
    });
  }

  private void testSuccessfulAclResponse(
      MockHttpServletResponse response1,
      MockHttpServletResponse response2,
      BiConsumer<String, String> aclAssertions) throws UnsupportedEncodingException {
    if (response1.getStatus() == 200) {
      aclAssertions.accept("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", response1.getContentAsString());
    } else if (response2.getStatus() == 200) {
      aclAssertions.accept("uaa-client:credhub_test", response2.getContentAsString());
    }
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
                    + "\"name\":\"" + SECRET_NAME + "\","
                    + "\"access_control_entries\":[{"
                    + "\"actor\":\"mtls:app:uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\","
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
                    + "\"name\":\"" + SECRET_NAME + "\", "
                    + "\"access_control_entries\":[{"
                    + "\"actor\":\"mtls:app:uaa-client:credhub_test\","
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
