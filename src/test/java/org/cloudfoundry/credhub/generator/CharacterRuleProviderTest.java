package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;

import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class CharacterRuleProviderTest {

  @Test
  public void getCharacterRules_createdCharacterRulesFromDefaultParameters() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);

    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.Digit),
        usesCharacters(EnglishCharacterData.LowerCase),
        usesCharacters(EnglishCharacterData.UpperCase)
    ));
    assertThat(characterRules, not(hasItem(usesCharacters(CredHubCharacterData.Hex))));
  }

  @Test
  public void getCharacterRules_canCreateCharacterRulesWithoutUppercase() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeUpper(true);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(2));
    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.LowerCase),
        usesCharacters(EnglishCharacterData.Digit)
    ));
    assertThat(characterRules, not(containsInAnyOrder(
        usesCharacters(EnglishCharacterData.UpperCase),
        usesCharacters(CredHubCharacterData.Special),
        usesCharacters(CredHubCharacterData.Hex)
    )));
  }

  @Test
  public void getCharacterRules_canCreateCharacterRulesWithoutLowercase() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(2));
    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.UpperCase),
        usesCharacters(EnglishCharacterData.Digit)
    ));
    assertThat(characterRules, not(containsInAnyOrder(
        usesCharacters(EnglishCharacterData.LowerCase),
        usesCharacters(CredHubCharacterData.Special),
        usesCharacters(CredHubCharacterData.Hex)
    )));
  }


  @Test
  public void getCharacterRules_canCreateCharacterRulesWithoutSpecialCharacters() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setIncludeSpecial(false);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(3));
    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.UpperCase),
        usesCharacters(EnglishCharacterData.LowerCase),
        usesCharacters(EnglishCharacterData.Digit)
    ));
    assertThat(characterRules, not(hasItem(usesCharacters(CredHubCharacterData.Special))));
    assertThat(characterRules, not(hasItem(usesCharacters(CredHubCharacterData.Hex))));
  }

  @Test
  public void getCharacterRules_canCreateCharacterRulesWithAllIncluded() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setIncludeSpecial(true);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(4));
    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.UpperCase),
        usesCharacters(EnglishCharacterData.LowerCase),
        usesCharacters(EnglishCharacterData.Digit),
        usesCharacters(CredHubCharacterData.Special)
    ));
  }

  @Test
  public void getCharacterRules_canCreateCharacterRulesWithoutNumbers() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeNumber(true);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(2));
    assertThat(characterRules, containsInAnyOrder(
        usesCharacters(EnglishCharacterData.UpperCase),
        usesCharacters(EnglishCharacterData.LowerCase)
    ));
    assertThat(characterRules, not(containsInAnyOrder(
        usesCharacters(EnglishCharacterData.Digit),
        usesCharacters(CredHubCharacterData.Special)
    )));
  }

  @Test
  public void getCharacterRules_returnsAnEmptyListWhenAllAreExcluded() {
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setIncludeSpecial(false);
    generationParameters.setExcludeNumber(true);
    generationParameters.setExcludeUpper(true);
    generationParameters.setExcludeLower(true);

    List<CharacterRule> characterRules = CharacterRuleProvider
        .getCharacterRules(generationParameters);
    assertThat(characterRules, iterableWithSize(0));
  }

  private Matcher<CharacterRule> usesCharacters(CharacterData characterData) {
    return new BaseMatcher<CharacterRule>() {

      @Override
      public boolean matches(final Object item) {
        final CharacterRule rule = (CharacterRule) item;
        return rule.getValidCharacters().equals(characterData.getCharacters());
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("getValidCharacters() should equal")
            .appendValue(characterData.getCharacters());
      }
    };
  }
}
