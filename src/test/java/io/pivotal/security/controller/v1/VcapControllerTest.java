package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.HashMap;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class VcapControllerTest {
  private VcapController subject;
  private MockMvc mockMvc;

  {
    beforeEach(() -> {
      subject = new VcapController(new JsonContextFactory());
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
        .build();
    });

    describe("/vcap", () -> {
      describe("#POST", () -> {
        describe("when no properly formatted credentials section exists", () -> {
          it("should fail", () -> {
            mockMvc.perform(post("/api/v1/vcap")
              .contentType(MediaType.APPLICATION_JSON)
              .content(JsonHelper.serialize(new HashMap()))
            ).andExpect(status().isUnprocessableEntity());
          });
        });
      });
    });
  }
}
