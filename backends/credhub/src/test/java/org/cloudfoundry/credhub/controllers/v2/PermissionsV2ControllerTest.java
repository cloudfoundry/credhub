package org.cloudfoundry.credhub.controllers.v2;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.handlers.SpyPermissionsHandler;
import org.cloudfoundry.credhub.permissions.PermissionsV2Controller;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.testhelpers.MockMvcFactory;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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

    mockMvc = MockMvcFactory.newSpringRestDocMockMvc(permissionsV2Controller, restDocumentation);
  }

  @Test
  public void GET__permissions_by_actor_and_path__returns_a_permission() throws Exception {
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE),
      "some-actor",
      UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456")
    );
    spyPermissionsHandler.setReturn_findByPathAndActor(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        get(PermissionsV2Controller.ENDPOINT)
          .header("Authorization", "Bearer [some-token]")
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
    assertThat(spyPermissionsHandler.getFindByPathAndActorCalledWithPath(), equalTo("/some-path"));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void GET__permissions_by_uuid__returns_a_permission() throws Exception {
    UUID guid = UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456");
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE),
      "some-actor",
      guid
    );
    spyPermissionsHandler.setReturn_getPermissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        get(PermissionsV2Controller.ENDPOINT + "/" + guid)
          .header("Authorization", "Bearer [some-token]")
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
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void POST__permissions__adds_a_leading_slash() throws Exception {
    UUID guid = UUID.fromString("abcd1234-ab12-ab12-ab12-abcdef123456");
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE),
      "some-actor",
      guid
    );

    final PermissionsV2Request expectedPermissionsV2Request = new PermissionsV2Request(
      "/some-path",
      "some-actor",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE)
    );

    spyPermissionsHandler.setReturn_writeV2Permissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        post(PermissionsV2Controller.ENDPOINT)
          .header("Authorization", "Bearer [some-token]")
          .contentType(MediaType.APPLICATION_JSON)
          .content("{\"path\":\"some-path\",\"actor\":\"some-actor\", \"operations\": [\"read\", \"write\"]}")
      )
      .andExpect(status().isCreated())
      .andReturn();

    PermissionsV2Request actualPermissionsV2Request = spyPermissionsHandler.getWriteV2PermissionCalledWithRequest();
    assertThat(actualPermissionsV2Request.getActor(), equalTo(expectedPermissionsV2Request.getActor()));
    assertThat(actualPermissionsV2Request.getPath(), equalTo(expectedPermissionsV2Request.getPath()));


    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void DELETE__permissions_by_uuid__returns_a_permission() throws Exception {
    String guid = "abcd1234-ab12-ab12-ab12-abcdef123456";
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE),
      "some-actor",
      UUID.fromString(guid)
    );
    spyPermissionsHandler.setReturn_deletePermissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        delete(PermissionsV2Controller.ENDPOINT + "/" + guid)
          .header("Authorization", "Bearer [some-token]")
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

    assertThat(spyPermissionsHandler.getDeletePermissionsGuid(), equalTo(guid));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void PUT__permissions__returns_a_permission() throws Exception {
    String guid = "abcd1234-ab12-ab12-ab12-abcdef123456";
    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE),
      "some-actor",
      UUID.fromString(guid)
    );
    spyPermissionsHandler.setReturn_putPermissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        put(PermissionsV2Controller.ENDPOINT + "/" + guid)
          .header("Authorization", "Bearer [some-token]")
          .contentType(MediaType.APPLICATION_JSON)
          .content("{\"path\":\"some-path\",\"actor\":\"some-actor\", \"operations\": [\"read\", \"write\"]}")
      )
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          "{methodName}",
          requestFields(
            fieldWithPath("path").description("The credential path").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string")),
            fieldWithPath("actor").description("The credential actor").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string")),
            fieldWithPath("operations").description("The list of permissions to be granted").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("array of strings"))
          )
        )
      )
      .andReturn();

    assertThat(spyPermissionsHandler.getPutPermissionGuid(), equalTo(guid));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);
  }

  @Test
  public void PATCH__permissions__returns_a_permission() throws Exception {
    String guid = "abcd1234-ab12-ab12-ab12-abcdef123456";

    final List<PermissionOperation> operations = Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE);

    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      operations,
      "some-actor",
      UUID.fromString(guid)
    );

    spyPermissionsHandler.setReturn_patchPermissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        patch(PermissionsV2Controller.ENDPOINT + "/" + guid)
          .header("Authorization", "Bearer [some-token]")
          .contentType(MediaType.APPLICATION_JSON)
          .content("{\"operations\": [\"read\", \"write\"]}")
      )
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          "{methodName}",
          requestFields(
            fieldWithPath("operations").description("The list of permissions to be granted").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("array of strings"))
          )
        )
      )
      .andReturn();

    assertThat(spyPermissionsHandler.getPatchPermissionGuid(), equalTo(guid));
    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);

  }

  @Test
  public void POST__permissions__returns_a_permission() throws Exception {
    String guid = "abcd1234-ab12-ab12-ab12-abcdef123456";

    final List<PermissionOperation> operations = Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE);

    final PermissionsV2View permissionsV2View = new PermissionsV2View(
      "some-path",
      operations,
      "some-actor",
      UUID.fromString(guid)
    );

    spyPermissionsHandler.setReturn_writeV2Permissions(permissionsV2View);

    final MvcResult mvcResult = mockMvc
      .perform(
        post(PermissionsV2Controller.ENDPOINT)
          .header("Authorization", "Bearer [some-token]")
          .contentType(MediaType.APPLICATION_JSON)
          .content("{\"path\":\"some-path\",\"actor\":\"some-actor\", \"operations\": [\"read\", \"write\"]}")
      )
      .andExpect(status().isCreated())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andDo(
        document(
          "{methodName}",
          requestFields(
            fieldWithPath("path").description("The credential path").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string")),
            fieldWithPath("actor").description("The credential actor").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("string")),
            fieldWithPath("operations").description("The list of permissions to be granted").attributes(key("default").value("none"),
              key("required").value("yes"), key("type").value("array of strings"))
          )
        )
      )
      .andReturn();

    final String actualResponseBody = mvcResult.getResponse().getContentAsString();
    final String expectedResponseBody = "{\"path\":\"some-path\",\"operations\":[\"read\", \"write\"],\"actor\":\"some-actor\",\"uuid\":\"abcd1234-ab12-ab12-ab12-abcdef123456\"}";
    JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true);

  }

}
