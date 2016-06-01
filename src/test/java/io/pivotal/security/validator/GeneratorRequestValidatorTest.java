package io.pivotal.security.validator;


import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.GeneratorRequest;
import io.pivotal.security.model.SecretParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class GeneratorRequestValidatorTest {
  @Autowired
  private MessageSource messageSource;


  private MessageSourceAccessor messageSourceAccessor;

  GeneratorRequestValidator validator = new GeneratorRequestValidator();

  @Test
  public void testValid() {
    GeneratorRequest generatorRequest = new GeneratorRequest();
    SecretParameters secretParameters = new SecretParameters();
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType("value");
    BindingResult bindingResult = new BeanPropertyBindingResult(generatorRequest, "generatorRequest");
    validator.validate(generatorRequest, bindingResult);
    assertThat(bindingResult.getErrorCount(), is(equalTo(0)));
  }

  @Test
  public void testInvalidParameters() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
    GeneratorRequest generatorRequest = new GeneratorRequest();
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeUpper(true);
    secretParameters.setExcludeLower(true);
    secretParameters.setExcludeSpecial(true);
    secretParameters.setExcludeNumber(true);
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType("value");
    BindingResult bindingResult = new BeanPropertyBindingResult(generatorRequest, "generatorRequest");
    validator.validate(generatorRequest, bindingResult);
    assertThat(bindingResult.getErrorCount(), is(equalTo(1)));
    String message = messageSourceAccessor.getMessage("error.excludes_all_charsets");

    assertThat(message, is(equalTo("The combination of parameters in the request is not allowed. Please validate your input and retry your request.")));
  }

  @Test
  public void testInvalidType() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
    GeneratorRequest generatorRequest = new GeneratorRequest();
    SecretParameters secretParameters = new SecretParameters();
    generatorRequest.setParameters(secretParameters);
    BindingResult bindingResult = new BeanPropertyBindingResult(generatorRequest, "generatorRequest");
    validator.validate(generatorRequest, bindingResult);
    assertThat(bindingResult.getErrorCount(), is(equalTo(1)));
    String message = messageSourceAccessor.getMessage("error.secret_type_invalid");

    assertThat(message, is(equalTo("The request does not include a valid type. Please validate your input and retry your request.")));
  }

  @Test
  public void testInvalidParametersAndType() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
    GeneratorRequest generatorRequest = new GeneratorRequest();
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeUpper(true);
    secretParameters.setExcludeLower(true);
    secretParameters.setExcludeSpecial(true);
    secretParameters.setExcludeNumber(true);
    generatorRequest.setParameters(secretParameters);
    generatorRequest.setType("bad_type");
    BindingResult bindingResult = new BeanPropertyBindingResult(generatorRequest, "generatorRequest");
    validator.validate(generatorRequest, bindingResult);
    assertThat(bindingResult.getErrorCount(), is(equalTo(2)));
    String message = messageSourceAccessor.getMessage("error.excludes_all_charsets");

    assertThat(message, is(equalTo("The combination of parameters in the request is not allowed. Please validate your input and retry your request.")));
  }

}

