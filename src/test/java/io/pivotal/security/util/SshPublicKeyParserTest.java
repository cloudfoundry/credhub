package io.pivotal.security.util;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.TestConstants.SSH_PUBLIC_KEY_4096;
import static io.pivotal.security.helper.TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class SshPublicKeyParserTest {

  {
    it("return null if public key is null", () -> {
      SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser(null);
      assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
      assertThat(sshPublicKeyParser.getComment(), equalTo(null));
      assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
    });

    it("should return null when given an invalid format", () -> {
      SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser(
          "AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1Op/vBLg+7pveOtiZqZQK4RVnQlRsttVelIZM"
              + "n8iafQQxv2xRqb2/np+9ErsTqby+9ninr8E4mxgWCs3Ew/K7Rnuzg9EEyfypB76cSzHZHHt"
              + "k9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z1yb4oEaAmAv/TAGbrKX7Ql"
              + "Hc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6XkcgXkn524SrqBR5BBT0"
              + "1WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMbzgOshcQj6o"
              + "/XaswSMUH4UR");
      assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
      assertThat(sshPublicKeyParser.getComment(), equalTo(null));
      assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
    });

    it("should return null when given another invalid format", () -> {
      SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser("          ");
      assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
      assertThat(sshPublicKeyParser.getComment(), equalTo(null));
      assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
    });

    describe("when the key is missing a valid prefix", () -> {
      it("should return null", () -> {
        SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser("invalid");

        assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
        assertThat(sshPublicKeyParser.getComment(), equalTo(null));
        assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
      });
    });

    describe("when the key is not valid base64", () -> {
      it("should return null", () -> {
        SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser("ssh-rsa so=invalid");

        assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
        assertThat(sshPublicKeyParser.getComment(), equalTo(null));
        assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
      });
    });

    describe("when the key is base64-encoded but invalid", () -> {
      it("should return null", () -> {
        SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser(
            "as qwe0qwe qwe qwe qweqwe das"
        );

        assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
        assertThat(sshPublicKeyParser.getComment(), equalTo(null));
        assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
      });
    });

    describe("#getKeyLength", () -> {
      it("should return the length of the public key (when no comment)", () -> {
        assertThat(new SshPublicKeyParser(SSH_PUBLIC_KEY_4096).getKeyLength(), equalTo(4096));
      });

      it("should still return the length when there is a comment", () -> {
        assertThat(
            new SshPublicKeyParser(SSH_PUBLIC_KEY_4096_WITH_COMMENT).getKeyLength(),
            equalTo(4096));
      });
    });

    describe("#getComment", () -> {
      it("should return a comment when there is one", () -> {
        assertThat(
            new SshPublicKeyParser(SSH_PUBLIC_KEY_4096_WITH_COMMENT).getComment(),
            equalTo("dan@foo"));
      });

      it("should return a empty string when there is none", () -> {
        assertThat(
            new SshPublicKeyParser(SSH_PUBLIC_KEY_4096).getComment(),
            equalTo(""));
      });

      it("should return all parts of a comment with spaces in it", () -> {
        String publicKeyWithSpacesInComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExa"
            + "dHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJS"
            + "HzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6m"
            + "G+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUn"
            + "kLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxG"
            + "kKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMM"
            + "gBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38x"
            + "XXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0"
            + "rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7"
            + "ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ"
            + "== comment with spaces";

        assertThat(new SshPublicKeyParser(publicKeyWithSpacesInComment).getComment(),
            equalTo("comment with spaces"));
      });
    });

    describe("#getPublicKeyFingerPrint", () -> {
      String validSshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1Op/vBLg+7pve"
          + "OtiZqZQK4RVnQlRsttVelIZMn8iafQQxv2xRqb2/n+9ErsTqby+9ninr8E4mxgWCs3Ew/K7Rnuzg9"
          + "EEyfypB76cSzHZHHtk9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z1yb4oEaAmAv"
          + "/TAGbrKX7QlHc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6XkcgXkn524SrqBR"
          + "5BBT01WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMbzgOshcQj6o/"
          + "XaswSMUH4UR";

      it("should compute SHA-256 fingerprint from the public key", () -> {
        assertThat(new SshPublicKeyParser(validSshPublicKey).getFingerprint(),
            equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA"));
      });

      describe("when the key has carriage returns in it", () -> {
        it("should compute SHA-256 fingerprint from the public key", () -> {
          assertThat(
              new SshPublicKeyParser(validSshPublicKey + '\n').getFingerprint(),
              equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA")
          );
        });
      });

      it("should compute SHA-256 fingerprint from the public key if a comment is present", () -> {
        String sshPublicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1O"
            + "p/vBLg+7pveOtiZqZQK4RVnQlRsttVelIZMn8iafQQxv2xRqb2/n+9ErsTqby+9ninr8E4mxgWCs3"
            + "Ew/K7Rnuzg9EEyfypB76cSzHZHHtk9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z"
            + "1yb4oEaAmAv/TAGbrKX7QlHc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6Xkcg"
            + "Xkn524SrqBR5BBT01WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMb"
            + "zgOshcQj6o/XaswSMUH4UR    bob@example.com";

        assertThat(new SshPublicKeyParser(sshPublicKeyWithComment).getFingerprint(),
            equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA"));
      });
    });
  }
}
