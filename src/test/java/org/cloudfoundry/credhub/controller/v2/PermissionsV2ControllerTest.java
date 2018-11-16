package org.cloudfoundry.credhub.controller.v2;

import org.cloudfoundry.credhub.handler.StubPermissionsHandler;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.http.MediaType;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.UUID;

import static java.util.Collections.emptyList;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
public class PermissionsV2ControllerTest {

  private MockMvc mockMvc;
  private StubPermissionsHandler stubPermissionsHandler;

  @Rule
  public final JUnitRestDocumentation restDocumentation = new JUnitRestDocumentation();

  @Before
  public void setUp() {
    stubPermissionsHandler = new StubPermissionsHandler();
    final PermissionsV2Controller permissionsV2Controller = new PermissionsV2Controller(stubPermissionsHandler);

    mockMvc = MockMvcBuilders
      .standaloneSetup(permissionsV2Controller)
      .alwaysDo(print())
      .apply(documentationConfiguration(this.restDocumentation))
      .build();
  }

  @Test
  public void GET__api_v2_permissions__returns_a_permission() throws Exception {
    PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      emptyList(),
      "some-actor",
      UUID.nameUUIDFromBytes("some-uuid".getBytes())
    );
    stubPermissionsHandler.setReturn_findByPathAndActor(permissionsV2View);

    MvcResult mvcResult = mockMvc
      .perform(
        get(PermissionsV2Controller.endpoint)
          .contentType(MediaType.APPLICATION_JSON)
          .param("path", "/some-path")
          .param("actor", "some-actor")
      )
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          PermissionsV2Controller.endpoint.replaceFirst("/", ""),
          requestParameters(
            parameterWithName("path").description("The credential path"),
            parameterWithName("actor").description("The credential actor")
          ),
          responseFields(
            fieldWithPath("path").description("The path that represents the credential"),
            fieldWithPath("operations").description("The operations that are permitted to be done with the credential. Available operations are: " + PermissionOperation.getCommaSeparatedPermissionOperations()),
            fieldWithPath("actor").description("The username that can interact with the credential"),
            fieldWithPath("uuid").description("The unique identifier that represents the credential")
          )
        )
      )
      .andReturn();

    String actualResponseBody = mvcResult.getResponse().getContentAsString();
    String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[],\"actor\":\"some-actor\",\"uuid\":\"48faba92-5492-3e23-b262-75e30a7ddb6a\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }
}
