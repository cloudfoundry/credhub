package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.validation.ValidationException;
import java.time.Instant;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@ActiveProfiles({"unit-test", "FakeUuidGenerator"})
public class SecretsControllerTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  @InjectMocks
  SecretsController subject;

  @Mock
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Mock
  NamedSecretSetHandler namedSecretSetHandler;

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private String secretName;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      secretName = uniquify("secret-name");
    });

    it("can generate secrets", () -> {
      when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
          .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(secretName, "some value"), null, null));

      final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{\"type\":\"value\"}");

      mockMvc.perform(post)
          .andExpect(status().isOk())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.type").value("value"))
          .andExpect(jsonPath("$.value").value("some value"))
          .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
          .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));

      final NamedValueSecret namedSecret = (NamedValueSecret) secretRepository.findOneByName(secretName);
      assertThat(namedSecret.getValue(), equalTo("some value"));
    });

    describe("setting a secret", () -> {
      final String otherValue = "some other value";

      beforeEach(() -> {
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(secretName, otherValue), null, null));

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"" + otherValue + "\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value(otherValue))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("persists the secret", () -> {
        final NamedValueSecret namedSecret = (NamedValueSecret) secretRepository.findOneByName(secretName);
        assertThat(namedSecret.getValue(), equalTo(otherValue));
      });

      it("preserves secrets when updating without the overwrite flag", () -> {
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenThrow(new UnsupportedOperationException());

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"special value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.value").value("some other value"));
      });

      it("can update a secret", () -> {
        final String specialValue = "special value";

        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new DefaultMapping() {
              @Override
              public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
                ((NamedValueSecret) namedSecret).setValue(specialValue);
                return namedSecret;
              }
            });

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"" + specialValue + "\"," +
                "  \"parameters\":{\"overwrite\":true}" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.value").value(specialValue));
      });

      it("can delete a secret", () -> {
        mockMvc.perform(delete("/api/v1/data/" + secretName))
            .andExpect(status().isOk());
      });
    });

    it("returns for 400 when the handler raises an exception", () -> {
      when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
          .thenReturn(new DefaultMapping() {
            @Override
            public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
              throw new ValidationException("error.type_mismatch");
            }
          });

      final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{" +
              "  \"type\":\"value\"," +
              "  \"value\":\"some value\"" +
              "}");

      mockMvc.perform(put)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.error").value("The credential type cannot be modified. Please delete the credential if you wish to create it with a different type."));
    });
  }
}