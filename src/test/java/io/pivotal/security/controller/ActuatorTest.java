package io.pivotal.security.controller;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {CredentialManagerApp.class})
@WebAppConfiguration
public class ActuatorTest extends HtmlUnitTestBase {

  @Test
  public void info() throws Exception {
    String expectedJson = "{\"app\":{\"name\":\"Pivotal Credential Manager\",\"version\":\"0.1.0\"}}";

    mockMvc.perform(get("/info"))
        .andExpect(status().isOk())
        .andExpect(content().json(expectedJson));
  }
}