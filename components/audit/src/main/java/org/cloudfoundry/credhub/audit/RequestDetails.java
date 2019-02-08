package org.cloudfoundry.credhub.audit;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;

import static com.fasterxml.jackson.databind.SerializationFeature.FAIL_ON_EMPTY_BEANS;

public interface RequestDetails {
  default String toJSON() {
    final String result;
    try {
      final ObjectMapper mapper = new ObjectMapper();
      mapper.configure(FAIL_ON_EMPTY_BEANS, false);
      result = mapper.writeValueAsString(this);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }

    return result;
  }

  OperationDeviceAction operation();
}
