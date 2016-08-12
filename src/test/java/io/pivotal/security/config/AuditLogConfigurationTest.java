package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.AuditRecordRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.autoTransactional;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@WebAppConfiguration
@ActiveProfiles({"unit-test", "AuditLogConfigurationTest", "NoExpirationSymmetricKeySecurityConfiguration"})
public class AuditLogConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  AuditRecordRepository auditRecordRepository;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);
    autoTransactional(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
      auditRecordRepository.deleteAll();
    });

    afterEach(() -> {
      auditRecordRepository.deleteAll();
    });

    describe("when a request to set credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder put = put("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .content("{\"type\":\"value\",\"credential\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(put)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential update operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_update"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to generate a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder post = post("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"value\"}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(post)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential_update operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_update"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to delete a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder delete = delete("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"value\"}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(delete)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for credential_delete operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_delete"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to retrieve a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder get = get("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(get)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for credential_access operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to set or generate a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder put = put("/api/v1/ca/bar")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"ca\":{\"certificate\":\"my_cert\",\"private\":\"private_key\"}}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(put)
            .andExpect(status().isOk());

        MockHttpServletRequestBuilder generate = post("/api/v1/ca/baz")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"parameters\":{\"common_name\":\"baz.com\"}}")
            .header("X-Forwarded-For", "3.3.3.3,4.4.4.4")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(generate)
            .andExpect(status().isOk());
      });

      it("logs an audit record for ca_update operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(2L));

        OperationAuditRecord auditRecord1 = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord1.getPath(), equalTo("/api/v1/ca/bar"));
        assertThat(auditRecord1.getOperation(), equalTo("ca_update"));
        assertThat(auditRecord1.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord1.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));

        OperationAuditRecord auditRecord2 = auditRecordRepository.findAll().get(1);
        assertThat(auditRecord2.getPath(), equalTo("/api/v1/ca/baz"));
        assertThat(auditRecord2.getOperation(), equalTo("ca_update"));
        assertThat(auditRecord2.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord2.getXForwardedFor(), equalTo("3.3.3.3,4.4.4.4"));
      });
    });

    describe("when a request to retrieve a CA is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder get = get("/api/v1/ca/bar")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT).header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(get)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for ca_access operation", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/ca/bar"));
        assertThat(auditRecord.getOperation(), equalTo("ca_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request has multiple X-Forwarded-For headers set", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder put = put("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .header("X-Forwarded-For", "3.3.3.3")
            .content("{\"type\":\"value\",\"credential\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(put)
            .andExpect(status().isOk());
      });

      it("logs all X-Forwarded-For values", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2,3.3.3.3"));
      });
    });
  }
}
