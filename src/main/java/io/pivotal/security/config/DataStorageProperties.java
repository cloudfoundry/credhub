package io.pivotal.security.config;

import com.google.common.base.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.HashMap;
import java.util.Map;

/** excluding DataSourceAutoConfiguration allows us to set dynamic Hibernate dialect
at runtime, based on requested data-storage.type */
@EnableAutoConfiguration(exclude={DataSourceAutoConfiguration.class})
@ConfigurationProperties("data-storage")
public class DataStorageProperties {
  @Autowired
  ConfigurableEnvironment environment;

  @NotNull(message = "The data-storage.type configuration property is required.")
  @Pattern(regexp = "in-memory|postgres|mysql", message = "The data-storage.type configuration " +
      "property must be \"mysql\", \"postgres\", or \"in-memory\".")
  private String type;

  private String username;
  private String password;
  private String host;
  private String port;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  @PostConstruct
  public void init() {
    Map<String, Object> map = new HashMap<>();
    MapPropertySource propertySource = new MapPropertySource("data-storage", map);

    if ("in-memory".equals(getType())) {
      map.put("spring.jpa.database-platform", "org.hibernate.dialect.H2Dialect");
    } else {
      if (Strings.isNullOrEmpty(getUsername())) {
        MessageSourceAccessor messageSourceAccessor = new MessageSourceAccessor(messageSource());
        throw new RuntimeException(messageSourceAccessor.getMessage("error.database_requires_credentials"));
      }
      map.put("spring.datasource.username", getUsername());
      map.put("spring.datasource.password", getPassword());
      map.put("spring.jpa.hibernate.ddl-auto", "create-drop");
      if ("postgres".equals(getType())) {
        map.put("spring.datasource.url", "jdbc:postgresql://localhost:5432/credhub");
        map.put("spring.jpa.database-platform", "org.hibernate.dialect.PostgreSQLDialect");
      } else if ("mysql".equals(getType())) {
        map.put("spring.datasource.url", "jdbc:mysql://" + getHost() + ":" + getPort() + "/credhub" );
        map.put("spring.jpa.database-platform", "org.hibernate.dialect.MySQL5InnoDBDialect");
      }
    }
    environment.getPropertySources().addFirst(propertySource);
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public void setPort(String port) {
    this.port = port;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public String getHost() {
    return host;
  }

  public String getPort() {
    return port;
  }

  public MessageSource messageSource() {
    ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
    messageSource.setBasenames("messages");
    messageSource.setDefaultEncoding("UTF-8");
    messageSource.setCacheSeconds(1);
    return messageSource;
  }
}
