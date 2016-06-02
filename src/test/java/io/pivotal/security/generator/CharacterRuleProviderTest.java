package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.SecretParameters;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.passay.CharacterRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CharacterRuleProviderTest {

  @Autowired
  CharacterRuleProvider subject;

  @Test
  public void getCharacterRules() {
    SecretParameters secretParameters = new SecretParameters();

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(4));
  }

  @Test
  public void getCharacterRulesWithoutUppercase() {
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeUpper(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("abc"),
        hasCharacters("123"),
        hasCharacters("#$%")
    ));
  }

  @Test
  public void getCharacterRulesWithoutLowercase() {
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeLower(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("123"),
        hasCharacters("#$%")
    ));
  }

  @Test
  public void getCharacterRulesWithoutSpecial() {
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeSpecial(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("abc"),
        hasCharacters("123")
    ));
  }

  @Test
  public void getCharacterRulesWithoutNumber() {
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeNumber(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("abc"),
        hasCharacters("#$%")
    ));
  }

  @Test
  public void getCharacterRulesWithoutAny() {
    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeSpecial(true);
    secretParameters.setExcludeNumber(true);
    secretParameters.setExcludeUpper(true);
    secretParameters.setExcludeLower(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(0));
  }

  private Matcher<CharacterRule> hasCharacters(String characters) {
    return new BaseMatcher<CharacterRule>() {

      @Override
      public boolean matches(final Object item) {
        final CharacterRule foo = (CharacterRule) item;
        return foo.getValidCharacters().contains(characters);
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("getValidCharacters() should include").appendValue(characters);
      }

    };
  }

}