package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.runner.RunWith;
import org.passay.CharacterRule;

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
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(3));
      });

      it("can create character rules without uppercase", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setExcludeUpper(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(2));
        assertThat(characterRules, containsInAnyOrder(
            hasCharacters("abc"),
            hasCharacters("123")
        ));
        assertThat(characterRules, not(containsInAnyOrder(
            hasCharacters("ABC"),
            hasCharacters("#$%")
        )));
      });

      it("can create character rules without lowercase", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setExcludeLower(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(2));
        assertThat(characterRules, containsInAnyOrder(
            hasCharacters("ABC"),
            hasCharacters("123")
        ));
        assertThat(characterRules, not(containsInAnyOrder(
            hasCharacters("abc"),
            hasCharacters("#$%")
        )));
      });

      it("can create character rules without special characters", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setIncludeSpecial(false);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(3));
        assertThat(characterRules, containsInAnyOrder(
            hasCharacters("ABC"),
            hasCharacters("abc"),
            hasCharacters("123")
        ));
        assertThat(characterRules, not(hasItem(
            hasCharacters("#$%")
        )));
      });

      it("can create character rules with all included", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setIncludeSpecial(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(4));
        assertThat(characterRules, containsInAnyOrder(
            hasCharacters("ABC"),
            hasCharacters("abc"),
            hasCharacters("123"),
            hasCharacters("#$%")
        ));
      });

      it("can create character rules without number", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setExcludeNumber(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(2));
        assertThat(characterRules, containsInAnyOrder(
            hasCharacters("ABC"),
            hasCharacters("abc")
        ));
        assertThat(characterRules, not(containsInAnyOrder(
            hasCharacters("123"),
            hasCharacters("#$%")
        )));
      });

      it("can create character rules with hex only", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setOnlyHex(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
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
      });

      it("ignores other rules when hex only", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setOnlyHex(true);
        secretParameters.setExcludeUpper(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
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
      });

      it("returns empty list when all are excluded", () -> {
        PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
        secretParameters.setIncludeSpecial(false);
        secretParameters.setExcludeNumber(true);
        secretParameters.setExcludeUpper(true);
        secretParameters.setExcludeLower(true);

        List<CharacterRule> characterRules = CharacterRuleProvider.getCharacterRules(secretParameters);
        assertThat(characterRules, iterableWithSize(0));
      });
    });
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
