package io.pivotal.security.controller.v1.health;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@ActiveProfiles("unit-test")
public class HealthControllerTest {

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  @InjectMocks
  private HealthController subject;

  @Mock
  private DataSourceHealthIndicator dataSourceHealthIndicator;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    });

    it("can answer that we're unhealthy", () -> {
      doAnswer((invocation) -> {
        invocation.getArgumentAt(0, Health.Builder.class).down(new RuntimeException("some error"));
        return null; })
          .when(dataSourceHealthIndicator).doHealthCheck(any(Health.Builder.class));

      mockMvc.perform(get("/health"))
          .andExpect(status().isOk())
          .andExpect(content().json("{\"db\": {\"status\":\"DOWN\",\"error\":\"java.lang.RuntimeException: some error\"}}"));
    });

    it("can answer that we're healthy", () -> {
      doAnswer((invocation) -> {
        invocation.getArgumentAt(0, Health.Builder.class).up();
        return null; })
          .when(dataSourceHealthIndicator).doHealthCheck(any(Health.Builder.class));

      mockMvc.perform(get("/health"))
          .andExpect(status().isOk())
          .andExpect(content().json("{\"db\": {\"status\":\"UP\"}}"));
    });
  }
}