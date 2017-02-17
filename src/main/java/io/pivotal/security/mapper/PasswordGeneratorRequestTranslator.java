package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.secret.Password;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;

@Component
public class PasswordGeneratorRequestTranslator implements RequestTranslator<NamedPasswordSecret>, SecretGeneratorRequestTranslator<PasswordGenerationParameters, NamedPasswordSecret> {

  @Autowired
  PassayStringSecretGenerator stringSecretGenerator;

  @Override
  public PasswordGenerationParameters validRequestParameters(DocumentContext parsed, NamedPasswordSecret entity) {
    PasswordGenerationParameters secretParameters;

    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);
    if (Boolean.TRUE.equals(regenerate)) {
      List<Object> values = parsed.read("$..*");
      if (values.size() > 2) {
        throw new ParameterizedValidationException("error.invalid_regenerate_parameters");
      }
      secretParameters = entity.getGenerationParameters();
      if (secretParameters == null) {
        throw new ParameterizedValidationException("error.cannot_regenerate_non_generated_credentials");
      }
    } else {
      secretParameters = new PasswordGenerationParameters();
      Optional.ofNullable(parsed.read("$.parameters.length", Integer.class))
          .ifPresent(secretParameters::setLength);
      Optional.ofNullable(parsed.read("$.parameters.exclude_lower", Boolean.class))
          .ifPresent(secretParameters::setExcludeLower);
      Optional.ofNullable(parsed.read("$.parameters.exclude_upper", Boolean.class))
          .ifPresent(secretParameters::setExcludeUpper);
      Optional.ofNullable(parsed.read("$.parameters.exclude_number", Boolean.class))
          .ifPresent(secretParameters::setExcludeNumber);
      Optional.ofNullable(parsed.read("$.parameters.include_special", Boolean.class))
          .ifPresent(secretParameters::setIncludeSpecial);
      Optional.ofNullable(parsed.read("$.parameters.only_hex", Boolean.class))
          .ifPresent(secretParameters::setOnlyHex);

      if (!secretParameters.isValid()) {
        throw new ParameterizedValidationException("error.excludes_all_charsets");
      }
    }
    return secretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedPasswordSecret entity, DocumentContext documentContext) {
    PasswordGenerationParameters requestParameters = validRequestParameters(documentContext, entity);
    Password secret = stringSecretGenerator.generateSecret(requestParameters);
    entity.setPasswordAndGenerationParameters(secret.getPassword(), requestParameters);
  }

  @Override
  public Set<String> getValidKeys() {
    return of(
        "$['type']",
        "$['name']",
        "$['overwrite']",
        "$['regenerate']",
        "$['parameters']",
        "$['parameters']['length']",
        "$['parameters']['exclude_lower']",
        "$['parameters']['exclude_upper']",
        "$['parameters']['exclude_number']",
        "$['parameters']['include_special']",
        "$['parameters']['only_hex']"
      );
  }
}
