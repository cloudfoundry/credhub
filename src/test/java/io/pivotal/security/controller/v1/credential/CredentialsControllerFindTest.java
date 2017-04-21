package io.pivotal.security.controller.v1.credential;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.FindCredentialResult;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.helper.AuditingHelper.verifyAuditing;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialsControllerFindTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  CredentialDataService credentialDataService;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private final String credentialName = "/my-namespace/subTree/credential-name";

  private ResultActions response;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("finding credential", () -> {
      describe("finding credentials by name-like, i.e. partial names, case-insensitively", () -> {
        describe("when search term does not include a leading slash", () -> {
          beforeEach(() -> {
            String substring = credentialName.substring(4).toUpperCase();
            doReturn(
                singletonList(new FindCredentialResult(frozenTime, credentialName))
            ).when(credentialDataService).findContainingName(substring);
            final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + substring)
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON);

            this.response = mockMvc.perform(get);
          });

          it("should return the credential metadata", () -> {
            this.response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.credentials[0].name").value(credentialName))
                .andExpect(jsonPath("$.credentials[0].version_created_at").value(frozenTime.toString()));
          });

          it("persists an audit entry", () -> {
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_FIND, null, "/api/v1/data", 200);
          });
        });
      });

      describe("finding credentials by path", () -> {
        beforeEach(() -> {
          String substring = credentialName.substring(0, credentialName.lastIndexOf("/"));
          doReturn(
              singletonList(new FindCredentialResult(frozenTime, credentialName))
          ).when(credentialDataService).findStartingWithPath(substring);

          final String path = substring;
          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the credential metadata", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials[0].name").value(credentialName))
              .andExpect(jsonPath("$.credentials[0].version_created_at").value(frozenTime.toString()));
        });

        it("should only find paths that start with the specified substring case-independently", () -> {
          final String path = "namespace";

          assertTrue(credentialName.contains(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("should return all children which are prefixed with the path case-independently", () -> {
          final String path = "/my-namespace";
          doReturn(
              singletonList(new FindCredentialResult(frozenTime, credentialName))
          ).when(credentialDataService).findStartingWithPath(path.toUpperCase());

          assertTrue(credentialName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(1)));
        });

        it("should not findCredentialsUsingPath paths which start an existing path but matches incompletely", () -> {
          final String path = "/my-namespace/subTr";

          assertTrue(credentialName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("persists an audit entry", () -> {
          verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_FIND, null, "/api/v1/data", 200);
        });
      });

      describe("finding all paths", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?paths=true")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);
          doReturn(
              Arrays.asList("my-namespace/", "my-namespace/subTree/")
          ).when(credentialDataService).findAllPaths();

          this.response = mockMvc.perform(get);
        });

        it("returns all possible paths for the table of existing credentials", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.paths[0].path").value("my-namespace/"))
              .andExpect(jsonPath("$.paths[1].path").value("my-namespace/subTree/"));
        });
      });
    });
  }
}
