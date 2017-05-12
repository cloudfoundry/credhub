package io.pivotal.security.controller.v1;

import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
public class InfoControllerTest {

  private MockMvc mockMvc;
  private InfoController infoController;

  @Before
  public void beforeEach() {
    infoController = new InfoController("https://uaa.url.example.com", "1.1.1.1", "notCredHubLol");

    mockMvc = MockMvcBuilders
        .standaloneSetup(infoController)
        .alwaysDo(print())
        .build();
  }

  @Test
  public void infoController_givenInfoPath_respondsWithApplicationInfo() throws Exception {
    mockMvc.perform(get("/info"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.auth-server.url").value("https://uaa.url.example.com"))
        .andExpect(jsonPath("$.app.version").value("1.1.1.1"))
        .andExpect(jsonPath("$.app.name").value("notCredHubLol"));
  }
}
