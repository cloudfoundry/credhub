package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.config.VersionProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
public class InfoControllerTest {

  private MockMvc mockMvc;

  @Autowired
  private VersionProvider versionProvider;

  @Before
  public void beforeEach() {
    final InfoController infoController = new InfoController(
        "https://uaa.url.example.com"
    );

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
        .andExpect(jsonPath("$.app.name").value("CredHub"));
  }
}
