package io.pivotal.security.oauth;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class RequestToOperationTranslatorTest {
  RequestToOperationTranslator pathToOperationTranslator;

  {
    describe("Credential requests", () -> {
      beforeEach(() -> {
        pathToOperationTranslator = new RequestToOperationTranslator("/api/v1/data/foo");
      });

      it("should return credential_update for POST /api/v1/data/{item}", () -> {
        pathToOperationTranslator.setMethod("POST");
        assertThat(pathToOperationTranslator.translate(), equalTo("credential_update"));
      });

      it("should return credential_update for PUT /api/v1/data/{item}", () -> {
        pathToOperationTranslator.setMethod("PUT");
        assertThat(pathToOperationTranslator.translate(), equalTo("credential_update"));
      });

      it("should return credential_update for GET /api/v1/data/{item}", () -> {
        pathToOperationTranslator.setMethod("GET");
        assertThat(pathToOperationTranslator.translate(), equalTo("credential_access"));
      });

      it("should return credential_update for DELETE /api/v1/data/{item}", () -> {
        pathToOperationTranslator.setMethod("DELETE");
        assertThat(pathToOperationTranslator.translate(), equalTo("credential_delete"));
      });
    });

    describe("CA requests", () -> {
      beforeEach(() -> {
        pathToOperationTranslator = new RequestToOperationTranslator("/api/v1/ca/foo");
      });

      it("should return ca_update for POST /api/v1/ca/{item}", () -> {
        pathToOperationTranslator.setMethod("POST");
        assertThat(pathToOperationTranslator.translate(), equalTo("ca_update"));
      });

      it("should return ca_update for PUT /api/v1/ca/{item}", () -> {
        pathToOperationTranslator.setMethod("PUT");
        assertThat(pathToOperationTranslator.translate(), equalTo("ca_update"));
      });

      it("should return ca_update for GET /api/v1/ca/{item}", () -> {
        pathToOperationTranslator.setMethod("GET");
        assertThat(pathToOperationTranslator.translate(), equalTo("ca_access"));
      });
    });
  }
}