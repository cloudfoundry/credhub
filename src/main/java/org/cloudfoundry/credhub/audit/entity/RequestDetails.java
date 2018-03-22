package org.cloudfoundry.credhub.audit.entity;

import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;

public interface RequestDetails {
  default String toJSON() {
    String result;
    try {
      result = new ObjectMapper().writeValueAsString(this);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    return result;
  }

  OperationDeviceAction operation();
}
