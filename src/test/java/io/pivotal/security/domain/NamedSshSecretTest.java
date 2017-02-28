package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNull;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
public class NamedSshSecretTest {

  private NamedSshSecret subject;

  private UUID encryptionKeyUuid;

  {
    beforeEach(() -> {
      subject = new NamedSshSecret("/Foo");
    });

    it("returns type ssh", () -> {
      assertThat(subject.getSecretType(), equalTo("ssh"));
    });

    describe("#getKeyLength", () -> {
      it("should return the length of the public key (when no comment)", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyOfLength4096 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ==";

        subject.setPublicKey(publicKeyOfLength4096);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });

      it("should still return the length when there is a comment", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyOfLength4096 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== dan@foo";

        subject.setPublicKey(publicKeyOfLength4096);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });
    });

    describe("#getComment", () -> {
      it("should return a comment when there is one", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== dan@foo";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo("dan@foo"));
      });

      it("should return a empty string when there is none", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ==";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo(""));
      });

      it("should return all parts of a comment with spaces in it", () -> {
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== comment with spaces";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo("comment with spaces"));
      });
    });

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        encryptionKeyUuid = UUID.randomUUID();

        subject = new NamedSshSecret("/foo");
        subject.setPublicKey("fake-public-key");
        subject.setEncryptedValue("fake-private-key".getBytes());
        subject.setNonce("fake-nonce".getBytes());
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);

        NamedSshSecret copy = new NamedSshSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/foo"));
        assertThat(copy.getPublicKey(), equalTo("fake-public-key"));
        assertThat(copy.getEncryptedValue(), equalTo("fake-private-key".getBytes()));
        assertThat(copy.getNonce(), equalTo("fake-nonce".getBytes()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });

    describe("#getPublicKeyFingerPrint", () -> {
      it("should compute SHA-256 fingerprint from the public key", () -> {
        String sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKGE4+UYSH1Op/vBLg+7pveOtiZqZQK4RVnQlRsttVelIZMn8iafQQxv2xRqb2/n+9ErsTqby+9ninr8E4mxgWCs3Ew/K7Rnuzg9EEyfypB76cSzHZHHtk9j2qejwkZwTrBvRV4NA7irAqX5s6v+tKa/xX0PwB1UhLPJ3Z1yb4oEaAmAv/TAGbrKX7QlHc0TLjjkIIA/fAiD7NFOBaQVaSWvL+SBfgBRbxQ4QXluPF9uOX6XkcgXkn524SrqBR5BBT01WIzEreZzmGlZQMWR1wnO7j7ogubinwulZkVLf/ufX68I2+6sIlFELelKcFMbzgOshcQj6o/XaswSMUH4UR";
        subject = new NamedSshSecret("/foo");
        subject.setPublicKey(sshPublicKey);
        assertThat(
            subject.getPublicKeyFingerprint(),
            equalTo("Ngft7Y3Aap0RoLTVAaOzQE1KXz1wo3bpzz4k9KV7TqA"));
      });

      it("return null if public key is null", () -> {
        subject = new NamedSshSecret("/foo");
        assertNull(subject.getPublicKeyFingerprint());
      });
    });
  }
}
