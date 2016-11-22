package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.service.DatabaseAuditLogService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.controller.v1.CaController.API_V1_CA;
import static io.pivotal.security.entity.AuditingOperationCode.CA_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CA_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "CaControllerAuditLogTest", "NoExpirationSymmetricKeySecurityConfiguration"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CaControllerAuditingLogTest {

  @Mock
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  @InjectMocks
  DatabaseAuditLogService auditLogService;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this, true);


    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });


    describe("when a request to retrieve a CA is served", () -> {
      beforeEach(() -> {
        doUnsuccessfulFetch("/api/v1/ca?name=bar&current=true");
      });

      it("logs an audit record for ca_access operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(API_V1_CA));
        assertThat(auditRecord.getOperation(), equalTo(CA_ACCESS.toString()));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to set or generate a credential is served", () -> {
      it("when setting the CA, it logs an audit record for ca_update operation", () -> {
        MockHttpServletRequestBuilder set = put(API_V1_CA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"name\":\"bar\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());

        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);
        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord record = recordCaptor.getValue();
        assertThat(record.getPath(), equalTo(API_V1_CA));
        assertThat(record.getOperation(), equalTo(CA_UPDATE.toString()));
        assertThat(record.getRequesterIp(), equalTo("12345"));
        assertThat(record.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));

      });

      it("when generating the CA, it logs an audit record for ca_update operation", () -> {
        MockHttpServletRequestBuilder generate = post(API_V1_CA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"name\":\"baz\",\"parameters\":{\"common_name\":\"baz.com\"}}")
            .header("X-Forwarded-For", "3.3.3.3,4.4.4.4")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(generate)
            .andExpect(status().isOk());


        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);
        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord record = recordCaptor.getValue();
        assertThat(record.getPath(), equalTo(API_V1_CA));
        assertThat(record.getOperation(), equalTo(CA_UPDATE.toString()));
        assertThat(record.getRequesterIp(), equalTo("12345"));
        assertThat(record.getXForwardedFor(), equalTo("3.3.3.3,4.4.4.4"));
      });
    });
  }

  private void doUnsuccessfulFetch(String urlPath) throws Exception {
    MockHttpServletRequestBuilder get = get(urlPath)
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
  }
}
