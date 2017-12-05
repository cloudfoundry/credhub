package org.cloudfoundry.credhub;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.cloudfoundry.credhub.config.JsonContextFactory;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cloudfoundry.credhub.util.TimeModuleFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

@SpringBootApplication
@EnableJpaAuditing(dateTimeProviderRef = "currentTimeProvider")
public class CredentialManagerApp {

  public static void main(String[] args) {
    SpringApplication.run(CredentialManagerApp.class, args);
  }

  @Bean
  public Module javaTimeModule() {
    return TimeModuleFactory.createTimeModule();
  }

  @Bean
  public JsonContextFactory jsonContextFactory() {
    return new JsonContextFactory();
  }

  @Bean(name = "currentTimeProvider")
  public CurrentTimeProvider currentTimeProvider() {
    return new CurrentTimeProvider();
  }

  @Bean
  public Jackson2ObjectMapperBuilder jacksonBuilder(Module javaTimeModule) {
    Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
    builder.modules(javaTimeModule);
    builder.failOnUnknownProperties(true);
    builder.propertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
    return builder;
  }

  @Bean
  public X509ExtensionUtils x509ExtensionUtils() throws OperatorCreationException {
    return new X509ExtensionUtils(new BcDigestCalculatorProvider().get(
        new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));
  }

  @Bean
  public EmbeddedServletContainerCustomizer servletContainerCustomizer() {
    return (factory) -> ((TomcatEmbeddedServletContainerFactory) factory)
        .addConnectorCustomizers((connector) -> ((AbstractHttp11Protocol<?>) connector.getProtocolHandler())
            .setUseServerCipherSuitesOrder(Boolean.toString(true)));
  }

  @Bean
  public MessageSourceAccessor messageSourceAccessor(MessageSource messageSource) {
    return new MessageSourceAccessor(messageSource);
  }
}
