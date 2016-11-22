package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.passay.CharacterRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CharacterRuleProviderTest {

  @Autowired
  CharacterRuleProvider subject;

  @Test
  public void getCharacterRules() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(4));
  }

  @Test
  public void getCharacterRulesWithoutUppercase() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setExcludeUpper(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("abc"),
        hasCharacters("123"),
        hasCharacters("#$%")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("ABC")
    )));
  }

  @Test
  public void getCharacterRulesWithoutLowercase() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setExcludeLower(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("123"),
        hasCharacters("#$%")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("abc")
    )));
  }

  @Test
  public void getCharacterRulesWithoutSpecial() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setExcludeSpecial(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("abc"),
        hasCharacters("123")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("#$%")
    )));
  }

  @Test
  public void getCharacterRulesWithoutNumber() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setExcludeNumber(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("ABC"),
        hasCharacters("abc"),
        hasCharacters("#$%")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("123")
    )));
  }

  @Test
  public void getCharacterRulesWithHexOnly() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setOnlyHex(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(2));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("123"),
        hasCharacters("ABC")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("abc")
    )));
    assertThat(characterRules, not(hasItem(
        hasCharacters("GH")
    )));
  }

  @Test
  public void getCharacterRulesWithHexOnlyIgnoresOtherRules() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
    secretParameters.setOnlyHex(true);
    secretParameters.setExcludeUpper(true);

    List<CharacterRule> characterRules = subject.getCharacterRules(secretParameters);
    assertThat(characterRules, iterableWithSize(2));
    assertThat(characterRules, containsInAnyOrder(
        hasCharacters("123"),
        hasCharacters("ABC")
    ));
    assertThat(characterRules, not(hasItem(
        hasCharacters("abc")
    )));
    assertThat(characterRules, not(hasItem(
        hasCharacters("GH")
    )));
  }

  @Test
  public void getCharacterRulesWithoutAny() {
    PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
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
