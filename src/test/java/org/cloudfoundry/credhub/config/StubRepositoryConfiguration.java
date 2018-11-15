package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.repository.PermissionRepository;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.repository.StubPermissionRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;

@Profile("stub-repositories")
@Configuration
public class StubRepositoryConfiguration {

  @Bean
  public PermissionRepository getStubPermissionRepository() {

    StubPermissionRepository stubPermissionRepository = new StubPermissionRepository();

    PermissionData permissionData = new PermissionData(
      "/some-path",
      "uaa-client:user-a",
      newArrayList(
        PermissionOperation.READ,
        PermissionOperation.WRITE
      )
    );

    permissionData.setUuid(UUID.nameUUIDFromBytes("some-permission-uuid".getBytes()));

    stubPermissionRepository.setReturn_findByPathAndAnchor(permissionData);

    return stubPermissionRepository;
  }
}
