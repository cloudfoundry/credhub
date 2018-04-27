package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;

import java.io.IOException;

public interface RequestDetails {
  default String toJSON() {
    String result;
    try {
      ObjectMapper mapper = new ObjectMapper();
      mapper.configure(SerializationConfig.Feature.FAIL_ON_EMPTY_BEANS, false);
      result = mapper.writeValueAsString(this);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    return result;
  }

  OperationDeviceAction operation();
}
