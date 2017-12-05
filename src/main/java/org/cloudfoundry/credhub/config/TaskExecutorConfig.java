package org.cloudfoundry.credhub.config;

import java.util.concurrent.Executor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@EnableAsync
@SuppressWarnings("unused")
class TaskExecutorConfig {

  @Bean
  public Executor threadPoolTaskExecutor() {
    return new ThreadPoolTaskExecutor();
  }
}
