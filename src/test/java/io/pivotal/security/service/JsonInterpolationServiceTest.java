package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedJsonSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.assertj.core.util.Maps;
import org.junit.runner.RunWith;

import java.io.InvalidObjectException;
import java.util.Map;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

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

          NamedJsonSecret jsonSecret1 = mock(NamedJsonSecret.class);
          doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonSecret1).getValue();

          NamedJsonSecret jsonSecret2 = mock(NamedJsonSecret.class);
          doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonSecret2).getValue();

          NamedJsonSecret jsonSecret3 = mock(NamedJsonSecret.class);
          Map<String, String> jsonSecrets = Maps.newHashMap("secret3-1", "secret3-1-value");
          jsonSecrets.put("secret3-2", "secret3-2-value");
          doReturn(jsonSecrets).when(jsonSecret3).getValue();

          SecretDataService mockSecretDataService = mock(SecretDataService.class);

          doReturn(
            jsonSecret1
          ).when(mockSecretDataService).findMostRecent("/cred1");

          doReturn(
            jsonSecret2
          ).when(mockSecretDataService).findMostRecent("/cred2");

          doReturn(
            jsonSecret3
          ).when(mockSecretDataService).findMostRecent("/cred3");

          DocumentContext response = subject.interpolateCredhubReferences(inputJson, mockSecretDataService);

          Map<String, Object> firstCredentialsBlock = response.read("$.VCAP_SERVICES.p-config-server[0].credentials");
          Map<String, Object> secondCredentialsBlock = response.read("$.VCAP_SERVICES.p-config-server[1].credentials");
          Map<String, Object> secondServiceCredentials = response.read("$.VCAP_SERVICES.p-something-else[0].credentials");

          assertThat(firstCredentialsBlock.get("credhub-ref"), nullValue());
          assertThat(firstCredentialsBlock.size(), equalTo(1));
          assertThat(firstCredentialsBlock.get("secret1"), equalTo("secret1-value"));

          assertThat(secondCredentialsBlock.get("credhub-ref"), nullValue());
          assertThat(secondCredentialsBlock.size(), equalTo(1));
          assertThat(secondCredentialsBlock.get("secret2"), equalTo("secret2-value"));

          assertThat(secondServiceCredentials.get("credhub-ref"), nullValue());
          assertThat(secondServiceCredentials.size(), equalTo(2));
          assertThat(secondServiceCredentials.get("secret3-1"), equalTo("secret3-1-value"));
          assertThat(secondServiceCredentials.get("secret3-2"), equalTo("secret3-2-value"));
        });

        itThrows("an exception when credential is not NamedJSONSecret", ParameterizedValidationException.class, () -> {
          String inputJson = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [" +
            "      {" +
            "        \"credentials\": {" +
            "          \"credhub-ref\": \"((/password_cred))\"" +
            "        }," +
            "        \"label\": \"p-config-server\"" +
            "      }" +
            "    ]" +
            "  }" +
            "}";

          NamedPasswordSecret passwordSecret = mock(NamedPasswordSecret.class);

          SecretDataService mockSecretDataService = mock(SecretDataService.class);

          doReturn(
            passwordSecret
          ).when(mockSecretDataService).findMostRecent("/password_cred");

          subject.interpolateCredhubReferences(inputJson, mockSecretDataService);
        });

        itThrows("an exception when credential is not accessible in datastore", InvalidObjectException.class, () -> {
          String inputJson = "{" +
            "  \"VCAP_SERVICES\": {" +
            "    \"p-config-server\": [" +
            "      {" +
            "        \"credentials\": {" +
            "          \"credhub-ref\": \"((/missing_cred))\"" +
            "        }," +
            "        \"label\": \"p-config-server\"" +
            "      }" +
            "    ]" +
            "  }" +
            "}";

          SecretDataService mockSecretDataService = mock(SecretDataService.class);

          doReturn(
            null
          ).when(mockSecretDataService).findMostRecent("/missing_cred");

          subject.interpolateCredhubReferences(inputJson, mockSecretDataService);
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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when no properly formatted credentials section exists", () -> {
      it("is ignored", () -> {
        DocumentContext response = subject.interpolateCredhubReferences("{}", mock(SecretDataService.class));

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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when VCAP_SERVICES is not an object", () -> {
      it("is ignored", () -> {
        String inputJsonString = "{" +
            "  \"VCAP_SERVICES\":[]" +
            "}";
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

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
        DocumentContext response = subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));

        assertThat(parse(response.jsonString()), equalTo(parse(inputJsonString)));
      });
    });

    describe("when input is not even json", () -> {
      itThrows("should throw exception", InvalidJsonException.class, () -> {
        String inputJsonString = "</xml?>";
        subject.interpolateCredhubReferences(inputJsonString, mock(SecretDataService.class));
      });
    });
  }
}

