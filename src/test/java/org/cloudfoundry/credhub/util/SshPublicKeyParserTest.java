package org.cloudfoundry.credhub.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@RunWith(JUnit4.class)
public class SshPublicKeyParserTest {

  @Test
  public void returnNullIfPublicKeyIsNull() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(null);
    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void returnNullIfPublicKeyIsInvalid() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey("foobar");
    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void shouldReturnNullWhenGivenAnInvalidFormat() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1Op/vBLg+7pveOtiZqZQK4RVnQlRsttVelIZM"
            + "n8iafQQxv2xRqb2/np+9ErsTqby+9ninr8E4mxgWCs3Ew/K7Rnuzg9EEyfypB76cSzHZHHt"
            + "k9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z1yb4oEaAmAv/TAGbrKX7Ql"
            + "Hc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6XkcgXkn524SrqBR5BBT0"
            + "1WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMbzgOshcQj6o"
            + "/XaswSMUH4UR");
    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void shouldReturnNullWhenGivenAnotherInvalidFormat() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey("          ");
    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void whenTheKeyIsMissingAValidPrefix_shouldReturnNull() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey("invalid");

    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void whenTheKeyIsNotValidBase64_shouldReturnNull() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey("ssh-rsa so=invalid");

    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void whenTheKeyIsBase64EncodedButInvalid_shouldReturnNull() {
    SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(
        "as qwe0qwe qwe qwe qweqwe das"
    );

    assertThat(sshPublicKeyParser.getFingerprint(), equalTo(null));
    assertThat(sshPublicKeyParser.getComment(), equalTo(null));
    assertThat(sshPublicKeyParser.getKeyLength(), equalTo(0));
  }

  @Test
  public void getKeyLength_shouldReturnTheLengthOfThePublicKeyWithoutComment() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096);
    assertThat(
        sshPublicKeyParser.getKeyLength(), equalTo(4096));
  }

  @Test
  public void getKeyLength_shouldReturnTheLengthOfThePublicKeyWithComment() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);
    assertThat(
        sshPublicKeyParser.getKeyLength(), equalTo(4096));
  }

  @Test
  public void getComment_shouldReturnACommentWhenThereIsOne() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);

    assertThat(
        sshPublicKeyParser.getComment(),
        equalTo("dan@foo"));
  }

  @Test
  public void getComment_shouldReturnAnEmptyStringWhenThereIsNone() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096);

    assertThat(
        sshPublicKeyParser.getComment(),
        equalTo(""));
  }

  @Test
  public void getComment_shouldReturnAllPartsOfACommentWithSpacesInIt() {
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

    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(publicKeyWithSpacesInComment);

    assertThat(sshPublicKeyParser.getComment(),
        equalTo("comment with spaces"));
  }

  String validSshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1Op/vBLg+7pve"
      + "OtiZqZQK4RVnQlRsttVelIZMn8iafQQxv2xRqb2/n+9ErsTqby+9ninr8E4mxgWCs3Ew/K7Rnuzg9"
      + "EEyfypB76cSzHZHHtk9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z1yb4oEaAmAv"
      + "/TAGbrKX7QlHc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6XkcgXkn524SrqBR"
      + "5BBT01WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMbzgOshcQj6o/"
      + "XaswSMUH4UR";

  @Test
  public void getPublicKeyFingerprint_shouldComputeTheSHA256FingerprintFromThePublicKey() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(validSshPublicKey);

    assertThat(sshPublicKeyParser.getFingerprint(),
        equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA"));
  }

  @Test
  public void getPublicKeyFingerprint_whenTheKeyHasCarriageReturnsInIt_computesTheSHA256FingerprintFromThePublicKey() {
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(validSshPublicKey + '\n');

    assertThat(
        sshPublicKeyParser.getFingerprint(),
        equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA")
    );
  }

  @Test
  public void getPublicKeyFingerprint_shouldComputeSHA256FingerprintFromThePublicKeyIfACommentIsPresent() {
    String sshPublicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1O"
        + "p/vBLg+7pveOtiZqZQK4RVnQlRsttVelIZMn8iafQQxv2xRqb2/n+9ErsTqby+9ninr8E4mxgWCs3"
        + "Ew/K7Rnuzg9EEyfypB76cSzHZHHtk9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z"
        + "1yb4oEaAmAv/TAGbrKX7QlHc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6Xkcg"
        + "Xkn524SrqBR5BBT01WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMb"
        + "zgOshcQj6o/XaswSMUH4UR    bob@example.com";
    final SshPublicKeyParser sshPublicKeyParser = new SshPublicKeyParser();
    sshPublicKeyParser.setPublicKey(sshPublicKeyWithComment);

    assertThat(sshPublicKeyParser.getFingerprint(),
        equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA"));
  }
}
