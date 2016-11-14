package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.NamedCertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.mapper.CAGeneratorRequestTranslator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CaControllerTest {
  private static final Instant OLDER_FROZEN_TIME_INSTANT = Instant.ofEpochSecond(1300000000L);
  private static final Instant FROZEN_TIME_INSTANT = Instant.ofEpochSecond(1400000000L);
  private static final String UPDATED_AT_JSON = "\"updated_at\":\"" + FROZEN_TIME_INSTANT.toString() + "\"";
  private static final String OLDER_UPDATED_AT_JSON = "\"updated_at\":\"" + OLDER_FROZEN_TIME_INSTANT.toString() + "\"";
  private static final String CA_CREATION_JSON = "\"type\":\"root\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}";
  private static final String CA_RESPONSE_JSON = "{" + UPDATED_AT_JSON + "," + CA_CREATION_JSON + "}";

  @Autowired
  protected WebApplicationContext context;

  @Mock
  private NamedCertificateAuthorityDataService namedCertificateAuthorityDataService;

  @InjectMocks
  @Autowired
  private CaController caController;

  @Autowired
  @InjectMocks
  CAGeneratorRequestTranslator caGeneratorRequestTranslator;

  @Spy
  @Autowired
  BCCertificateGenerator certificateGenerator;

  @Spy
  @Autowired
  @InjectMocks
  AuditLogService auditLogService;

  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  private String uniqueName;
  private String urlPath;
  private UUID uuid;
  private NamedCertificateAuthority fakeGeneratedCa;

  private ResultActions response;
  private NamedCertificateAuthority originalCa;
  private NamedCertificateAuthority olderStoredCa;
  private NamedCertificateAuthority storedCa;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
      fakeTimeSetter.accept(FROZEN_TIME_INSTANT.toEpochMilli());
      uniqueName = "my-folder/ca-identifier";
      urlPath = "/api/v1/ca/" + uniqueName;

      uuid = UUID.randomUUID();
      fakeGeneratedCa = new NamedCertificateAuthority(uniqueName)
          .setType("root")
          .setCertificate("my_cert")
          .setPrivateKey("private_key")
          .setUuid(uuid)
          .setUpdatedAt(FROZEN_TIME_INSTANT);
    });

    describe("generating a ca", () -> {
      describe("when creating a new CA", () -> {
        beforeEach(() -> {
          doReturn(new CertificateAuthority(fakeGeneratedCa))
              .when(certificateGenerator).generateCertificateAuthority(any(CertificateSecretParameters.class));
          doReturn(
              fakeGeneratedCa
          ).when(namedCertificateAuthorityDataService).save(any(NamedCertificateAuthority.class));

          String requestJson = "{\"type\":\"root\",\"parameters\":{\"common_name\":\"test-ca\"}}";

          RequestBuilder requestBuilder = post(urlPath)
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);

          response = mockMvc.perform(requestBuilder);
        });

        it("can generate a ca", () -> {
          response
              .andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(content().json(CA_RESPONSE_JSON));
        });

        it("saves the generated ca in the DB", () -> {
          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(namedCertificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority savedCa = argumentCaptor.getValue();
          assertThat(savedCa.getName(), equalTo(uniqueName));
          assertThat(savedCa.getCertificate(), equalTo("my_cert"));
        });

        it("creates an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("ca_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("when the CA already exists in the database", () -> {
        beforeEach(() -> {
          setUpExistingCa();
          setUpCaSaving();

          String requestJson =
            "{" +
              "\"type\":\"root\"," +
              "\"parameters\":{" +
                "\"common_name\":\"test-ca\"" +
              "}" +
            "}";

          RequestBuilder requestBuilder = post(urlPath)
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);

          response = mockMvc.perform(requestBuilder);
        });

        it("should succeed", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(jsonPath("$.value.certificate").isString())
              .andExpect(jsonPath("$.value.private_key").value("new-private-key"))
              .andExpect(jsonPath("$.type").value("root"))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.updated_at").value(FROZEN_TIME_INSTANT.toString()));
        });

        it("should generate the new certificate", () -> {
          verify(certificateGenerator, times(1)).generateCertificateAuthority(any(CertificateSecretParameters.class));
        });

        it("saves a new CA in the database", () -> {
          ArgumentCaptor<NamedCertificateAuthority> copyArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          ArgumentCaptor<NamedCertificateAuthority> saveArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(originalCa, times(1)).copyInto(copyArgumentCaptor.capture());
          verify(namedCertificateAuthorityDataService, times(1)).save(saveArgumentCaptor.capture());

          NamedCertificateAuthority newCertificateAuthority = saveArgumentCaptor.getValue();
          assertNotNull(newCertificateAuthority.getUuid());
          assertThat(newCertificateAuthority.getUuid(), not(equalTo(originalCa.getUuid())));
          assertNotNull(newCertificateAuthority.getCertificate());
          assertThat(newCertificateAuthority.getCertificate(), not(equalTo(originalCa.getCertificate())));
        });
      });
    });

    it("returns 400 when json keys are invalid", () -> {
      final MockHttpServletRequestBuilder put = put("/api/v1/ca/test-ca")
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{" +
              "  \"type\":\"root\"," +
              "  \"bogus\":\"value\"" +
              "}");
      mockMvc.perform(put)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'bogus'. Please update or remove this parameter and retry your request."));
    });

    describe("setting a ca", () -> {
      describe("when creating a new CA", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          doReturn(
              new NamedCertificateAuthority(uniqueName)
                  .setType("root")
                  .setCertificate("my_cert")
                  .setPrivateKey("private_key")
                  .setUpdatedAt(FROZEN_TIME_INSTANT)
                  .setUuid(uuid)
          ).when(namedCertificateAuthorityDataService).save(any(NamedCertificateAuthority.class));
          String requestJson = "{" + CA_CREATION_JSON + "}";
          RequestBuilder requestBuilder = put(urlPath)
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);
          response = mockMvc.perform(requestBuilder);
        });

        it("returns the new root ca", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(content().json(CA_RESPONSE_JSON));
        });

        it("writes the new root ca to the DB", () -> {
          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          verify(namedCertificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority actual = argumentCaptor.getValue();

          assertThat(actual.getCertificate(), equalTo("my_cert"));
        });

        it("creates an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("ca_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("when updating an existing CA", () -> {
        beforeEach(() -> {
          setUpExistingCa();
          setUpCaSaving();

          String requestJson =
            "{" +
              "\"type\":\"root\"," +
              "\"value\":{" +
                "\"certificate\":\"new-certificate\"," +
                "\"private_key\":\"new-private-key\"" +
              "}" +
            "}";

          RequestBuilder requestBuilder = put(urlPath)
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);

          response = mockMvc.perform(requestBuilder);
        });

        it("should succeed", () -> {
          String expectedJson =
              "{" +
                "\"value\":{" +
                  "\"certificate\":\"new-certificate\"," +
                  "\"private_key\":\"new-private-key\"" +
                "}," +
                "\"type\":\"root\"," +
                "\"id\":\"" + uuid.toString() + "\"," +
                UPDATED_AT_JSON +
              "}";
          response
              .andExpect(status().isOk())
              .andExpect(content().json(expectedJson, true));
        });

        it("should create a new entity for it", () -> {
          ArgumentCaptor<NamedCertificateAuthority> copyArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          ArgumentCaptor<NamedCertificateAuthority> saveArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(originalCa, times(1)).copyInto(copyArgumentCaptor.capture());
          verify(namedCertificateAuthorityDataService, times(1)).save(saveArgumentCaptor.capture());

          NamedCertificateAuthority newCertificateAuthority = saveArgumentCaptor.getValue();
          assertNotNull(newCertificateAuthority.getUuid());
          assertThat(newCertificateAuthority.getUuid(), not(equalTo(originalCa.getUuid())));
          assertThat(newCertificateAuthority.getCertificate(), equalTo("new-certificate"));
        });

        it("creates an audit record", () -> {
          verify(auditLogService).performWithAuditing(eq("ca_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });
    });

    describe("errors when setting a CA", () -> {
      it("put with only a certificate returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"value\":{\"certificate\":\"my_certificate\"}}");
      });

      it("put with only private returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"value\":{\"private_key\":\"my_private_key\"}}");
      });

      it("put without keys returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"value\":{}}");
      });

      it("put with empty request returns an error", () -> {
        requestWithError("{\"type\":\"root\"}");
      });

      it("put cert with garbage returns an error", () -> {
        String requestJson = "{\"value\":\"\" }";

        RequestBuilder requestBuilder = put(urlPath)
            .content(requestJson)
            .contentType(MediaType.APPLICATION_JSON_UTF8);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isBadRequest());
      });
    });

    describe("getting a ca", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();
        olderStoredCa = new NamedCertificateAuthority(uniqueName)
            .setType("root")
            .setCertificate("my-certificate-old")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setUpdatedAt(OLDER_FROZEN_TIME_INSTANT);
        uuid = UUID.randomUUID();
        storedCa = new NamedCertificateAuthority(uniqueName)
            .setType("root")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setUpdatedAt(FROZEN_TIME_INSTANT);
        doReturn(newArrayList(storedCa, olderStoredCa)).when(namedCertificateAuthorityDataService).findAllByName(eq(uniqueName));
        doReturn(storedCa).when(namedCertificateAuthorityDataService).findMostRecent(eq(uniqueName));
      });

      describe("by name", () -> {
        describe("as part of the path", () -> {
          it("returns the ca when the name is part of the path", () -> {
            String expectedJson = "{ \"data\": [" +
                "{"
                + UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            mockMvc.perform(get(urlPath))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJson, true));
          });

          it("handles missing name parameter", () -> {
            mockMvc.perform(get("/api/v1/ca"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Missing identifier. Please validate your input and retry your request."));
          });

          it("persists an audit entry when getting a ca", () -> {
            mockMvc.perform(get(urlPath))
                .andExpect(status().isOk());
            verify(auditLogService).performWithAuditing(eq("ca_access"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });

        describe("as a query parameter", () -> {
          it("returns the ca when the name is a request parameter", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            mockMvc.perform(get("/api/v1/ca?name=" + uniqueName))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          it("can limit results with the 'current' query parameter", () -> {
            String jsonWithOnlyOneCA = "{ \"data\": [" +
                "{"
                + UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=true", uniqueName);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(jsonWithOnlyOneCA, true));
          });

          it("returns the all results when the 'current' query parameter is false'", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=false", uniqueName);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          it("handles empty 'current' parameter as false", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_UPDATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=", uniqueName);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          it("handles empty name", () -> {
            mockMvc.perform(get("/api/v1/ca?name="))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Missing identifier. Please validate your input and retry your request."));
          });

          it("persists an audit entry when getting a ca", () -> {
            mockMvc.perform(get("/api/v1/ca?name=" + uniqueName))
                .andExpect(status().isOk());
            verify(auditLogService).performWithAuditing(eq("ca_access"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });
      });

      describe("when there are previous versions of a named key", () -> {
        it("returns all the versions", () -> {
          doReturn(newArrayList(fakeGeneratedCa, storedCa))
              .when(namedCertificateAuthorityDataService).findAllByName(eq(uniqueName));
          mockMvc.perform(get("/api/v1/ca?name=" + uniqueName))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.data").value(hasSize(2)))
              .andExpect(jsonPath("$.data[0].value.certificate").value("my_cert"))
              .andExpect(jsonPath("$.data[1].value.certificate").value("my-certificate"));
        });
      });
    });

    describe("by id", () -> {
      beforeEach(() -> {
        storedCa = new NamedCertificateAuthority(uniqueName)
            .setType("root")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setUpdatedAt(FROZEN_TIME_INSTANT);
        doReturn(storedCa)
            .when(namedCertificateAuthorityDataService)
            .findByUuid(eq("my-uuid"));

        MockHttpServletRequestBuilder get = get("/api/v1/ca?id=my-uuid")
            .accept(APPLICATION_JSON);

        response = mockMvc.perform(get);
      });

      it("returns the ca", () -> {
        String expectedJson = "{ \"data\": [" +
            "{"
            + UPDATED_AT_JSON + "," +
            "    \"type\":\"root\"," +
            "    \"value\":{" +
            "        \"certificate\":\"my-certificate\"," +
            "        \"private_key\":\"my-priv\"" +
            "    }," +
            "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
            "}" +
            "]" +
            "}";

        response.andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(expectedJson, true));
      });

      it("persists an audit entry when getting a ca", () -> {
        verify(auditLogService).performWithAuditing(eq("ca_access"), isA(AuditRecordParameters.class), any(Supplier.class));
      });
    });

    it("returns bad request for PUT with invalid type", () -> {
      String uuid = UUID.randomUUID().toString();
      String requestJson = "{\"type\":" + uuid + ",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = put(urlPath)
          .content(requestJson)
          .contentType(MediaType.APPLICATION_JSON_UTF8);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("returns bad request for generate POST with invalid type", () -> {
      String requestJson = "{\"type\":\"invalid-type\"}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = post(urlPath)
          .content(requestJson)
          .contentType(MediaType.APPLICATION_JSON_UTF8);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("get returns 404 when not found", () -> {
      String notFoundJson = "{\"error\": \"CA not found. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = get(urlPath)
          .contentType(MediaType.APPLICATION_JSON_UTF8);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isNotFound())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });
  }

  private void requestWithError(String requestJson) throws Exception {
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = put(urlPath)
        .content(requestJson)
        .contentType(MediaType.APPLICATION_JSON_UTF8);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  private void setUpExistingCa() {
    originalCa = spy(new NamedCertificateAuthority(uniqueName));
    originalCa.setUuid(UUID.randomUUID());
    originalCa.setCertificate("original-certificate");

    doReturn(originalCa)
        .when(namedCertificateAuthorityDataService).findMostRecent(anyString());
  }

  private void setUpCaSaving() {
    uuid = UUID.randomUUID();

    doAnswer(invocation -> {
      NamedCertificateAuthority certificateAuthority = invocation.getArgumentAt(0, NamedCertificateAuthority.class);
      certificateAuthority.setUpdatedAt(FROZEN_TIME_INSTANT);
      if (certificateAuthority.getUuid() == null) {
        certificateAuthority.setUuid(uuid);
      }
      return certificateAuthority.setPrivateKey("new-private-key");
    }).when(namedCertificateAuthorityDataService).save(any(NamedCertificateAuthority.class));
  }
}
