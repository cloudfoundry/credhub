package org.cloudfoundry.credhub.controller.v2;

import java.util.UUID;

import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.springframework.http.MediaType;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import org.cloudfoundry.credhub.handler.SpyPermissionsHandler;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
  public void GET__permissions_by_actor_and_path__returns_a_permission() throws Exception {
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      emptyList(),
      "some-actor",
      UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456")
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
          "{methodName}",
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
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void GET__permissions_by_uuid__returns_a_permission() throws Exception {
    UUID guid = UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456");
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      emptyList(),
      "some-actor",
      guid
    );
    spyPermissionsHandler.setReturn_getPermissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        get(PermissionsV2Controller.ENDPOINT + "/" + guid)
          .contentType(MediaType.APPLICATION_JSON)
      )
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          "{methodName}",
          requestParameters()
        )
      )
      .andReturn();

    assertThat(spyPermissionsHandler.getGetPermissionsCalledWithGuid(), equalTo(guid));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void POST__permissions__adds_a_leading_slash() throws Exception {
    UUID guid = UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456");
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
            "some-path",
            emptyList(),
            "some-actor",
            guid
    );
    final PermissionsV2Request permissionsV2Request = new PermissionsV2Request(
      "some-path",
      "some-actor",
      emptyList()
    );
    spyPermissionsHandler.setreturn_writeV2Permissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        post(PermissionsV2Controller.ENDPOINT)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .content("{\"path\":\"some-path\",\"actor\":\"some-actor\", \"operations\": []}")
      )
      .andExpect(status().isCreated())
      .andDo(
        document(
          "{methodName}",
          requestParameters()
        )
      )
      .andReturn();

    PermissionsV2Request actualPermissionsV2Request = spyPermissionsHandler.getWriteV2PermissionCalledWithRequest();
    assertThat(actualPermissionsV2Request.getActor(), equalTo("some-actor"));
    assertThat(actualPermissionsV2Request.getPath(), equalTo("/some-path"));


    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

}
