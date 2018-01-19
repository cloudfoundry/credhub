package org.cloudfoundry.credhub.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LunaProviderProperties {

  @Value("${hsm.partition:#{null}}")
  String partitionName;

  @Value("${hsm.partition_password:#{null}}")
  String partitionPassword;

  public String getPartitionName() {
    return partitionName;
  }

  public String getPartitionPassword() {
    return partitionPassword;
  }
}
