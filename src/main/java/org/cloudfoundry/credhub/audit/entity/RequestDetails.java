package org.cloudfoundry.credhub.audit.entity;

import java.io.IOException;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;

public interface RequestDetails {
  default String toJSON() {
    final String result;
    try {
      final ObjectMapper mapper = new ObjectMapper();
      mapper.configure(SerializationConfig.Feature.FAIL_ON_EMPTY_BEANS, false);
      result = mapper.writeValueAsString(this);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }

    return result;
  }

  OperationDeviceAction operation();
}
