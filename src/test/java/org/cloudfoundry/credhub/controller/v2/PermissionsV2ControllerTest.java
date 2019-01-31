package org.cloudfoundry.credhub.controller.v2;

import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import org.cloudfoundry.credhub.handler.SpyPermissionsHandler;
import org.cloudfoundry.credhub.util.StringUtil;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class PermissionsV2ControllerTest {

  @Rule
  public final JUnitRestDocumentation restDocumentation = new JUnitRestDocumentation();
  private MockMvc mockMvc;
  private SpyPermissionsHandler spyPermissionsHandler;

  @Before
  public void setUp() {
    spyPermissionsHandler = new SpyPermissionsHandler();
    final PermissionsV2Controller permissionsV2Controller = new PermissionsV2Controller(spyPermissionsHandler);

    mockMvc = MockMvcBuilders
      .standaloneSetup(permissionsV2Controller)
      .alwaysDo(print())
      .apply(
              documentationConfiguration(this.restDocumentation)
              .operationPreprocessors()
              .withRequestDefaults(prettyPrint())
              .withResponseDefaults(prettyPrint())
      )
      .build();
  }

  @Test
  public void GET__api_v2_permissions__returns_a_permission() throws Exception {
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      emptyList(),
      "some-actor",
      UUID.nameUUIDFromBytes("some-uuid".getBytes(StringUtil.UTF_8))
    );
    spyPermissionsHandler.setReturn_findByPathAndActor(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        get(PermissionsV2Controller.ENDPOINT)
          .contentType(MediaType.APPLICATION_JSON)
          .param("path", "some-path")
          .param("actor", "some-actor")
      )
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          PermissionsV2Controller.ENDPOINT.replaceFirst("/", ""),
          requestParameters(
            parameterWithName("path").description("The credential path").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string")),
            parameterWithName("actor").description("The credential actor").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string"))
          )
        )

      )
      .andReturn();

    assertThat(spyPermissionsHandler.getFindByPathAndActorCalledWithActor(), equalTo("some-actor"));
    assertThat(spyPermissionsHandler.getFindByPathAndActorCalledWithPath(), equalTo("some-path"));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[],\"actor\":\"some-actor\",\"uuid\":\"48faba92-5492-3e23-b262-75e30a7ddb6a\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }
}
