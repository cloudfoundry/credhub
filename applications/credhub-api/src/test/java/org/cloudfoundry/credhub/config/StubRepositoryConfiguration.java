package org.cloudfoundry.credhub.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.repositories.PermissionRepository;

import org.mockito.Mockito;

import static com.google.common.collect.Lists.newArrayList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;

@Profile("stub-repositories")
@Configuration
public class StubRepositoryConfiguration {

  @Bean
  public PermissionRepository getStubPermissionRepository() {

    final PermissionRepository mockPermissionRepository = Mockito.mock(PermissionRepository.class);

    final PermissionData permissionData = new PermissionData(
      "/some-path",
      "uaa-client:user-a",
      newArrayList(
        PermissionOperation.READ,
        PermissionOperation.WRITE
      )
    );

    permissionData.setUuid(UUID.nameUUIDFromBytes("some-permission-uuid".getBytes(UTF_8)));

    Mockito.when(mockPermissionRepository.findByPathAndActor(any(), any())).thenReturn(permissionData);

    return mockPermissionRepository;
  }
}
