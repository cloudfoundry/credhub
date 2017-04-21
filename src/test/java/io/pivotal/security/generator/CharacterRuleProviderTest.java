package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.StringGenerationParameters;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.runner.RunWith;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;

import java.util.List;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class CharacterRuleProviderTest {

  {
    describe("#getCharacterRules", () -> {
      it("creates character rules from default parameters", () -> {
        StringGenerationParameters generationParameters = new StringGenerationParameters();
        List<CharacterRule> characterRules = CharacterRuleProvider
            .getCharacterRules(generationParameters);

        assertThat(characterRules, containsInAnyOrder(
            usesCharacters(EnglishCharacterData.Digit),
            usesCharacters(EnglishCharacterData.LowerCase),
            usesCharacters(EnglishCharacterData.UpperCase)
        ));
        assertThat(characterRules, not(hasItem(usesCharacters(CredHubCharacterData.Hex))));
      });

      it("can create character rules without uppercase", () -> {
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
      });

      it("can create character rules without lowercase", () -> {
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
      });

      it("can create character rules without special characters", () -> {
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
      });

      it("can create character rules with all included", () -> {
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
      });

      it("can create character rules without number", () -> {
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
      });

      it("returns empty list when all are excluded", () -> {
        StringGenerationParameters generationParameters = new StringGenerationParameters();
        generationParameters.setIncludeSpecial(false);
        generationParameters.setExcludeNumber(true);
        generationParameters.setExcludeUpper(true);
        generationParameters.setExcludeLower(true);

        List<CharacterRule> characterRules = CharacterRuleProvider
            .getCharacterRules(generationParameters);
        assertThat(characterRules, iterableWithSize(0));
      });
    });
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
