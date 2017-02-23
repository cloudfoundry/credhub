package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedValueSecret;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_FIND;
import io.pivotal.security.fake.FakeAuditLogService;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.SecretView;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import org.mockito.Mockito;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerFindTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  FakeAuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/subTree/secret-name";

  private ResultActions response;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("finding secret", () -> {
      describe("finding credentials by name-like, i.e. partial names, case-insensitively", () -> {
        describe("when search term does not include a leading slash", () -> {
          beforeEach(() -> {
            String substring = secretName.substring(4).toUpperCase();
            NamedValueSecret namedValueSecret = new NamedValueSecret(secretName);
            namedValueSecret.setEncryptedValue("some value".getBytes());
            namedValueSecret.setVersionCreatedAt(frozenTime);
            doReturn(
                Arrays.asList(new SecretView(frozenTime, secretName))
            ).when(secretDataService).findContainingName(substring);
            final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + substring)
                .accept(APPLICATION_JSON);

            this.response = mockMvc.perform(get);
          });

          it("should return the secret metadata", () -> {
            this.response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.credentials[0].name").value(secretName))
                .andExpect(jsonPath("$.credentials[0].version_created_at").value(frozenTime.toString()));
          });

          it("persists an audit entry", () -> {
            ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
            verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

            assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_FIND));
          });
        });
      });

      describe("finding credentials by path", () -> {
        beforeEach(() -> {
          String substring = secretName.substring(0, secretName.lastIndexOf("/"));
          NamedValueSecret namedValueSecret = new NamedValueSecret(secretName);
          namedValueSecret.setEncryptedValue("some value".getBytes());
          namedValueSecret.setVersionCreatedAt(frozenTime);
          doReturn(
              Arrays.asList(new SecretView(frozenTime, secretName))
          ).when(secretDataService).findStartingWithPath(substring);

          final String path = substring;
          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the secret metadata", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials[0].name").value(secretName))
              .andExpect(jsonPath("$.credentials[0].version_created_at").value(frozenTime.toString()));
        });

        it("should only find paths that start with the specified substring case-independently", () -> {
          final String path = "namespace";

          assertTrue(secretName.contains(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("should return all children which are prefixed with the path case-independently", () -> {
          final String path = "/my-namespace";
          NamedValueSecret namedValueSecret = new NamedValueSecret("my-namespace");
          namedValueSecret.setEncryptedValue("some value".getBytes());
          namedValueSecret.setVersionCreatedAt(frozenTime);
          doReturn(
              Arrays.asList(new SecretView(frozenTime, secretName))
          ).when(secretDataService).findStartingWithPath(path.toUpperCase());

          assertTrue(secretName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(1)));
        });

        it("should not findSecretsUsingPath paths which start an existing path but matches incompletely", () -> {
          final String path = "/my-namespace/subTr";

          assertTrue(secretName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_FIND));
        });
      });

      describe("finding all paths", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?paths=true")
              .accept(APPLICATION_JSON);
          doReturn(
              Arrays.asList("my-namespace/", "my-namespace/subTree/")
          ).when(secretDataService).findAllPaths();

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

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
