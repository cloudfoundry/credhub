package io.pivotal.security.actuator;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.List;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {CredentialManagerApp.class})
@WebAppConfiguration
public class ActuatorIT {
    @Autowired
    private WebApplicationContext context;

    private List<String> actuatorEndpoints;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .build();

        actuatorEndpoints = Arrays.asList(
                "/info"
        );
    }

    @Test
    public void actuatorEndpoints() throws Exception {
        for (String endpoint : actuatorEndpoints) {
            mockMvc.perform(get(endpoint))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("Pivotal")))
                    .andExpect(content().string(containsString("v1")));
        }
    }
}