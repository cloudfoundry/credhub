package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.config.JsonContextFactory;
import org.junit.runner.RunWith;
import org.springframework.http.MediaType;

import java.util.Map;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class JsonInterpolationServiceTest {
  public JsonInterpolationService subject;

  {
    beforeEach(() -> {
      subject = new JsonInterpolationService(new JsonContextFactory());
    });

    describe("#interpolateCredhubReferences", () -> {
      describe("when properly formatted credentials section is found", () -> {
        it("should replace the credhub-ref element with something else", () -> {
          String inputJson = "{" +
              "  \"VCAP_SERVICES\": {" +
              "    \"p-config-server\": [" +
              "      {" +
              "        \"credentials\": {" +
              "          \"credhub-ref\": \"((/cred1))\"" +
              "        }," +
              "        \"label\": \"p-config-server\"" +
              "      }," +
              "      {" +
              "        \"credentials\": {" +
              "          \"credhub-ref\": \"((/cred2))\"" +
              "        }" +
              "      }" +
              "    ]," +
              "    \"p-something-else\": [" +
              "      {" +
              "        \"credentials\": {" +
              "          \"credhub-ref\": \"((/cred3))\"" +
              "        }," +
              "        \"something\": [\"p-config-server\"]" +
              "      }" +
              "    ]" +
              "  }" +
              "}";

          DocumentContext response = subject.interpolateCredhubReferences(inputJson);

          Map<String, Object> firstCredentialsBlock = response.read("$.VCAP_SERVICES.p-config-server[0].credentials");
          Map<String, Object> secondCredentialsBlock = response.read("$.VCAP_SERVICES.p-config-server[1].credentials");
          Map<String, Object> secondServiceCredentials = response.read("$.VCAP_SERVICES.p-something-else[0].credentials");

          assertThat(firstCredentialsBlock.get("credhub-ref"), nullValue());
          assertThat(firstCredentialsBlock.size(), equalTo(1));
          assertThat(secondCredentialsBlock.get("credhub-ref"), nullValue());
          assertThat(secondCredentialsBlock.size(), equalTo(1));
          assertThat(secondServiceCredentials.get("credhub-ref"), nullValue());
          assertThat(secondServiceCredentials.size(), equalTo(1));
        });
      });
    });
    describe("when the services properties do not have credentials", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [{" +
            "      \"blah\": {" +
            "        \"credhub-ref\": \"((/cred1))\"" +
            "       }," +
            "      \"label\": \"p-config-server\"" +
            "    }]" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when credentials is somewhere unexpected", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [{" +
            "      \"foo\": {" +
            "        \"credentials\": {" +
            "          \"credhub-ref\": \"((/cred1))\"" +
            "         }" +
            "       }," +
            "      \"label\": \"p-config-server\"" +
            "    }]" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when properties are not hashes", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [\"what is this?\"]" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("credentials is not a hash", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [{" +
            "      \"credentials\": \"moose\"," +
            "      \"label\": \"squirrel\"" +
            "    }]" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when no properly formatted credentials section exists", () -> {
      it("is ignored", () -> {
        DocumentContext response = subject.interpolateCredhubReferences("{}");

        assertThat(parse(response.jsonString()), equalTo(parse("{}")));
      });
    });

    describe("when no VCAP_SERVICES key is present", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"credentials\":{" +
            "    \"credhub-ref\":\"((/some/known/path))\"" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when VCAP_SERVICES is not an object", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\":[]" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when the services properties are not arrays", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": {" +
            "      \"credentials\": {" +
            "        \"credhub-ref\": \"((/cred1))\"" +
            "       }," +
            "      \"label\": \"p-config-server\"" +
            "    }" +
            "  }" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString);

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when input is not even json", () -> {
      itThrows("should throw exception", InvalidJsonException.class, () -> {
        String inputJsonString = "</xml?>";
        subject.interpolateCredhubReferences(inputJsonString);
      });
    });
  }
}

