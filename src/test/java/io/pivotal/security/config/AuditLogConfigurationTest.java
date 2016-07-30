package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.interceptor.AuditLogInterceptor;
import io.pivotal.security.interceptor.DatabaseAuditLogInterceptor;
import io.pivotal.security.repository.AuditRecordRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration
@WebAppConfiguration
@ActiveProfiles({"dev", "AuditLogConfigurationTest"})
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

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("when a request is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder post = post("/api/v1/data/foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + SecurityConfigurationTest.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"value\"}");

        mockMvc.perform(post)
            .andExpect(status().isOk());
      });

      afterEach(() -> {
        auditRecordRepository.deleteAll();
      });

      it("logs an audit record", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));

        OperationAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
      });
    });
  }

  @Configuration
  @Import(CredentialManagerApp.class)
  public static class TestConfiguration {

    @Bean
    @Profile("AuditLogConfigurationTest")
    public AuditLogInterceptor auditLogInterceptor() {
      return new DatabaseAuditLogInterceptor();
    }
  }
}
