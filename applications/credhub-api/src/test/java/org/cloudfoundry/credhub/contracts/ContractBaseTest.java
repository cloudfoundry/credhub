package org.cloudfoundry.credhub.contracts;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import io.restassured.module.mockmvc.RestAssuredMockMvc;
import org.cloudfoundry.credhub.CredHubApp;
import org.junit.Before;
import org.junit.runner.RunWith;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ActiveProfiles(profiles = {
  "dev-h2",
  "unit-test",
  "stub-repositories",
})
@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredHubApp.class)
@AutoConfigureMockMvc
public abstract class ContractBaseTest {

  @Autowired
  public WebApplicationContext webApplicationContext;

  @Before
  public void setUp() {

    RestAssuredMockMvc
      .mockMvc(
        MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build()
      );
  }
}
