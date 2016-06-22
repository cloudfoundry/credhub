package io.pivotal.security;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.Option;
import io.pivotal.security.entity.JpaAuditingHandlerRegistrar;
import io.pivotal.security.util.CurrentTimeProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static java.time.format.DateTimeFormatter.ofPattern;

@SpringBootApplication
@EnableJpaAuditing(dateTimeProviderRef = "currentTimeProvider")
@Import(JpaAuditingHandlerRegistrar.class)
public class CredentialManagerApp {
  public static final DateTimeFormatter TIMESTAMP_FORMAT = ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

  public static void main(String[] args) {
    SpringApplication.run(CredentialManagerApp.class, args);
  }

  @Bean
  Configuration getConfiguration() {
    return Configuration.defaultConfiguration()
        .addOptions(Option.SUPPRESS_EXCEPTIONS);
  }

  @Bean(name = "currentTimeProvider")
  public CurrentTimeProvider currentTimeProvider() {
    CurrentTimeProvider currentTimeProvider = new CurrentTimeProvider();
    return currentTimeProvider;
  }

  @Bean
  @Primary
  public ObjectMapper serializingObjectMapper() {
    ObjectMapper objectMapper = new ObjectMapper();
    JavaTimeModule javaTimeModule = new JavaTimeModule();
    javaTimeModule.addSerializer(LocalDateTime.class, new LocalDateSerializer());
    objectMapper.registerModule(javaTimeModule);
    return objectMapper;
  }

  public static class LocalDateSerializer extends JsonSerializer<LocalDateTime> {
    @Override
    public void serialize(LocalDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
      gen.writeString(value.format(TIMESTAMP_FORMAT));
    }
  }
}