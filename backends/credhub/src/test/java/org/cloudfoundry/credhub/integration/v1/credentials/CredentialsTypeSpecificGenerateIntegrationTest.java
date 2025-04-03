package org.cloudfoundry.credhub.integration.v1.credentials;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.CryptSaltFactory;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.generators.CertificateGenerator;
import org.cloudfoundry.credhub.generators.PasswordCredentialGenerator;
import org.cloudfoundry.credhub.generators.RsaGenerator;
import org.cloudfoundry.credhub.generators.SshGenerator;
import org.cloudfoundry.credhub.generators.UserGenerator;
import org.cloudfoundry.credhub.requests.DefaultCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.utils.MultiJsonPathMatcher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Parameterized.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CredentialsTypeSpecificGenerateIntegrationTest {

  @ClassRule
  public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();
  private static final String RSA_PUBLIC_KEY =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3jegX4fdAWXKAH1OVme8"
      + "uqG/2lU/f6ABRoHSk3tyHnaiIpxOfaNqi4iD0InYgYbuS5+CwCfJuRdL9XPQQ58x"
      + "0599POsOV0Gh6RxclprJoQMpRSSapBJUgMPAB9bl8MJUlmHWndD8Fpx/GxLKPlY4"
      + "oor8Ta3X3XVpNuSN3g9GPW7Hjbx91rJljmFY9IAQK4eQ5JfQeWLQxtsI7xtaj0Hk"
      + "9v04eOlt3Hifip4iYG7bEpfNdx0QhufbZM8d1j14ygtlIFMjycLzuyqq/OHQPnxs"
      + "z/VwE6c6nZU7S/oJBZApvahVIS8TVey4wMUY52Z8Doh+H525rZ1fA3ip2lN4HAfn"
      + "owIDAQAB";
  private static final String RSA_PRIVATE_KEY =
    "MIIEpQIBAAKCAQEA3jegX4fdAWXKAH1OVme8uqG/2lU/f6ABRoHSk3tyHnaiIpxO"
      + "faNqi4iD0InYgYbuS5+CwCfJuRdL9XPQQ58x0599POsOV0Gh6RxclprJoQMpRSSa"
      + "pBJUgMPAB9bl8MJUlmHWndD8Fpx/GxLKPlY4oor8Ta3X3XVpNuSN3g9GPW7Hjbx9"
      + "1rJljmFY9IAQK4eQ5JfQeWLQxtsI7xtaj0Hk9v04eOlt3Hifip4iYG7bEpfNdx0Q"
      + "hufbZM8d1j14ygtlIFMjycLzuyqq/OHQPnxsz/VwE6c6nZU7S/oJBZApvahVIS8T"
      + "Vey4wMUY52Z8Doh+H525rZ1fA3ip2lN4HAfnowIDAQABAoIBAQCBG7as6mYokrhb"
      + "snIaV6lakfHC67a58v/qtDDhiV6Tfn/TNheQfarAqS9UsVI+Z2P6QhIYjMVyKavz"
      + "TzeYolyzxL1h8HvjjHmC0/yjcAln6EtJJexHGXNJYPIoW947FN1KhkvIY4yjoodi"
      + "9nbU4wmCvte6Vh/ORpI712zpsNwxgh9ZW3sJESjONoQGcgnxuBHzzOl0OosI08Q9"
      + "m119TOhkfFafZzXsr6ywlIjpDM5SoYjURqHuCw5/H3sXiqFQtp8caVpXzWmYhyTz"
      + "NQn+7Mndud43QxI19QQ3jOReFE9LCJeH+/zMgRiWyARTplk+yKXLhjqTdGtgqb5Z"
      + "8DkzUq/pAoGBAPZC1l94QYJX1Zhc+cSeS9Z/GHiB3XDQuUDMlknsP0KgTYuSYSSX"
      + "RlW1EfM/7B0YC2vehgGx/dSnXhFBoySrLuTz6BaLgJKFaQellGaZj/65Igq/w4zp"
      + "dHAv1p0sItjxNBxw1/D0yrzBfGgbvjDvZDoE0Fo+7RJZj37zgbADV61fAoGBAOcB"
      + "XkKJQMwW5A2v8xngHfd1JmaD1aewYUFWqTcP7HuymC1Q09wV/tONBdE4STIQyivW"
      + "piS5hGNG9V4LqovELdG2ZUqlMzyCIkf2oRoYaORENZNLIIivde2oHyw6SmSJJFNc"
      + "2RNNe0LoZphCDjKujixKNtbYeMl3XWYDqjila2g9AoGBANQHiiIbHXRHgf20l8zF"
      + "apCdT4l6bxoSbF6xh/jP80u/T+ULPJ7PrNxgkbr536bRLAxNRN4yzVUKYcDD3d7V"
      + "kQPKSZsXs7T0LxFJbHPGZiewaPIOWCV8YCez2Lns5XgafX67XgH2EpTglufgcyoZ"
      + "BBe8S1RYd7Bj8lwg9xmAVz5LAoGBALSImzQAtEVL9nrD8YddYc4NHi+sBIQDEl7P"
      + "7Xr81OJvVwLDUm+EORz3733tMTcRbA8Kt9mnqtEzmXsgPu7wKKbmlw7ZQMufIE+B"
      + "bbJJNWB/9ibg5dIs3ksXwxT7kTw0+dC0lWnCefx2SAfiR9pQFQiED4ukrfE1eibJ"
      + "4nRWwzQ5AoGAHAs5aqjxDK7DMjuwjxH0DJOwKNFTtPPp3c2wkweqxG6jmg1G3Ml1"
      + "YdpRLONCCJOgLdXhfrKorfiBqNZuNcMR0EbvvZh6aM4JYxLPQsWBjrKsJW53LFyH"
      + "fFphcIDHhgtKr0EjyLCRs9UsXnjF16zrU+QBW4JnYFMjCNbAGOoAtvU=";
  private static final String PUBLIC_KEY =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDw47Rlo6bBmB8FRMjcP17v4bGQnGv"
      + "1JDtW5zP8oD8XiKlwSahAdXECwcHBDmO33GyGB2PGdOh5AxOIW9M8/KBWWyPdzqko"
      + "Ea291K52XfomhDwC+oKSS+USEOh4+VFHwq40gDz52Nz1FWqtQ/4QMx23WIci+j0ks"
      + "q6ZMJqajb6BoyM+qnHLRVbWsYveW6I/LRqWdQvUy4s3+2SWUdkQCTObstOI7xvhOJ"
      + "8E/Bt33BfkJluvG0E0dTzClycMdS6IgswI260BzNlMsgA+eNpI+ihi9/i1mUJlIxC"
      + "/vZ3Lb0jj6FkFYz2pANNR3k2beJmzkpsEHadxQfVD0vcGxoDaqnEv";
  private static final String CA =
    "-----BEGIN CERTIFICATE-----\n"
      + "MIIDPjCCAiagAwIBAgIUIgg7xZVYF3qFsUVAhAFldTvCDJ4wDQYJKoZIhvcNAQEL\n"
      + "BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTgwNjE1MTUwMDU3WhcNMTkw\n"
      + "NjE1MTUwMDU3WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\n"
      + "AQEBBQADggEPADCCAQoCggEBAM6z9Y/odS4pldElmK3syIbxhy5gPR5yvRIpEE89\n"
      + "yXEkAJjyW8+zIjZM6/bIEIkAOAObXWLbcqI/Wv+FSxsUq55IYIZlaBpoHjl5rsvv\n"
      + "inBbsKBChAPLuLBNNR8NJ/8gkZkeBsobBkkhTjZl1f6+GGAnLazqLxl8tyxwhNBe\n"
      + "dlONwozUuJ1Vlve65L+cuapnKlmYz+ZYd4f75mJcs2OPUmXhbhTK+RI0gtZC84Qg\n"
      + "0+pPheXjde/E8f0HrW2cO0wewxdAPnzD5MvQCZdc1ndpp2df4DZgLtxXozpLCSHF\n"
      + "LxhnOkEGjtmxHG8YelrXZ0QbsZOumuvbWmK71PTalOKSe4cCAwEAAaOBgzCBgDAd\n"
      + "BgNVHQ4EFgQUJbJRTUNhGiVXo/ELta+dlRCALwswUQYDVR0jBEowSIAUJbJRTUNh\n"
      + "GiVXo/ELta+dlRCALwuhGqQYMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tghQiCDvF\n"
      + "lVgXeoWxRUCEAWV1O8IMnjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB\n"
      + "AQAUM7zOD09vxMMGELbm3m+DgJOIhWm6zkibpzn1P1e7Pi7BOQ+2GvXBmn030yQU\n"
      + "O5rKLNv49up9XGViKsPfVjbmxWp9WbElNPW+dJyO3zLMMkFtm/1T39Y+/A1LH3ww\n"
      + "HSOnT3s54pSI66L9Mpiq+V2VmiOKEvoxy2mGQteMkXWSX31p0PlKMToV34TDIk9M\n"
      + "9XyxHVWTf5NLe/gUEIoZatdvMmANKmKBiUWI5Aqnh93a2TXDu2Q8WXc0U0W8hsbD\n"
      + "Wv7ec0Gguo4GtOomkmFIgXBLZd0ZqWywEjSGRy4us/71gBioTgCBMw8g75SzxX5u\n"
      + "hQHS5//LiA50aEI4X0k5TDQp\n"
      + "-----END CERTIFICATE-----";
  private static final String CERTIFICATE_PRIVATE_KEY =
    "MIIEowIBAAKCAQEAzrP1j+h1LimV0SWYrezIhvGHLmA9HnK9EikQTz3JcSQAmPJb\n"
      + "z7MiNkzr9sgQiQA4A5tdYttyoj9a/4VLGxSrnkhghmVoGmgeOXmuy++KcFuwoEKE\n"
      + "A8u4sE01Hw0n/yCRmR4GyhsGSSFONmXV/r4YYCctrOovGXy3LHCE0F52U43CjNS4\n"
      + "nVWW97rkv5y5qmcqWZjP5lh3h/vmYlyzY49SZeFuFMr5EjSC1kLzhCDT6k+F5eN1\n"
      + "78Tx/QetbZw7TB7DF0A+fMPky9AJl1zWd2mnZ1/gNmAu3FejOksJIcUvGGc6QQaO\n"
      + "2bEcbxh6WtdnRBuxk66a69taYrvU9NqU4pJ7hwIDAQABAoIBAGcpIXFFDtaPIppT\n"
      + "LTQAbMQMXu8iUN6VXQ9nNyCVMagp07KBopiySmzXTxzHFJmLZmlGbQEdjMS04fGM\n"
      + "0MMfOdexP5tTmPU06YC93iMh1fHlkO0qxUAvuGkk31Iz+rY1xvSoK7NKcYSl/qbf\n"
      + "hEGzFe9HHmCiMAeEWtbvARoNSvi/bYdMKPeHxepoBZbsGyca4J8HZxxDraci9HGM\n"
      + "jIiOmIR3Eene21yDlPhv78uKDsyzaQuWwodZnTc/MqgvXAbNqO743xkY2toYFjmQ\n"
      + "m1gl9aKr73ABcCRHKNQgJeM2hbNyaTDusxulwdl44HZWFRxLiQRjY370vYe/JwvQ\n"
      + "0jr7X+ECgYEA7sryXdoPknZtL3x7qOxn5w9bnDCUR2uL6vnZHXsmUmfpXjTgbqx4\n"
      + "5Y2gk2SywgKflEE9svxB0USObaON/Rnnc8pBHGEyLq10l2eE7CioEedLXqktWSuB\n"
      + "Ric7m3RIJHNQlA56IbTlCh6JrIhF2ZLIEWThl/ndGVfJ1jX+KkYioZ0CgYEA3ZkL\n"
      + "1a2CVeMXq/DfHa2jiNcHJhgMrkHwWGsa0KG5m6DNNwhj+NrEloVtDqpLdQCfNk7V\n"
      + "7Usj6vWNDUObL9cpQT0kF0qP1VcYKgK1GCq+GEwhAzIWYA5Djgtx59AEaEUJZrYa\n"
      + "T5I9pI6mdQqGsbV0RNwldKKYkGcr3EjFU7IWynMCgYEAocNBpGpQGju3g2+kpa5g\n"
      + "RJqWyJvwFuG4CxnuBpaiQzi5UmQnlVGpJHhoyvBwWBVG3TvE/Db+rzDt+z/MtCSU\n"
      + "MlBVA1CkmhJO5THvTbvM/zPcTuf0HG/oRwnUy15ecLLdZy7XdXYBonVFdmdqShWx\n"
      + "Cnd4i2dsa/qYdFBnOWQBmdECgYBodRWEEzdGHzdwYKn8Bnb5MUt4ZIvNtN2EAHDy\n"
      + "ednRh7pUv8rIau+SeLDQ4euR6soiQoVLR0lWH4vu/bhwk78ptpWFuSsWCOkmHIKb\n"
      + "MsLLF0/Ufs7XVsH3emOmP4NkV264EQ1UBv6xzGCg+WZG7N8y+odZdK/wGgIt48vI\n"
      + "yUE/CwKBgGsfJIiSYcvK5u6YeERHWYEqFcBY0s0WhdY+1YZsWxuv9jgmilaPomCt\n"
      + "EZyqglpqqjc0uqXEIBG4LUXI6mkou73gjURtlekTA+3jZPcNq1h9gRNukeEh+6bl\n"
      + "JaEuFCA4oM8WjNbXvE8ddtPCv7XoV11qUdWsgQ89ELsFonGmgIBG\n";
  private static final String PRIVATE_KEY =
    "MIIEpAIBAAKCAQEA8OO0ZaOmwZgfBUTI3D9e7+GxkJxr9SQ7Vucz/KA/F4ipcEmo\n"
      + "QHVxAsHBwQ5jt9xshgdjxnToeQMTiFvTPPygVlsj3c6pKBGtvdSudl36JoQ8AvqC\n"
      + "kkvlEhDoePlRR8KuNIA8+djc9RVqrUP+EDMdt1iHIvo9JLKumTCamo2+gaMjPqpx\n"
      + "y0VW1rGL3luiPy0alnUL1MuLN/tkllHZEAkzm7LTiO8b4TifBPwbd9wX5CZbrxtB\n"
      + "NHU8wpcnDHUuiILMCNutAczZTLIAPnjaSPooYvf4tZlCZSMQv72dy29I4+hZBWM9\n"
      + "qQDTUd5Nm3iZs5KbBB2ncUH1Q9L3BsaA2qpxLwIDAQABAoIBADoOdyTj60XPVvKb\n"
      + "IFnMwCHKYFQ9DtvXLqIEOQhSysHuQv/4EJ/wbhs+/WZ9BFWEv3cSAt8KwBiiQCvm\n"
      + "DaQuMqp9bsh/jU9F63zL7HxErAxqZFhHbf66YewXvR+i3w8PgZLPsWJ5/M7oqXw2\n"
      + "3d2jpC7THEa2ztOwaNos16YWMWrmod0qzCyT9w9QSuU8wRU/VVJ1x2BEoeeQSXuA\n"
      + "Uj4s8sCLZXvttx+IPbhpzDSad5oq5OZvw9glcwIuTlDM0nqPSy4AvU9+3jYjkxk5\n"
      + "QbSY9ty5l+XVCA/yc30wfuX/H+ZM7vNCD3qiHsT/ZEInNm0jpSuyOF+bZjnM7+0L\n"
      + "7OYeYNkCgYEA+VyP1MBPQt1u9v8rTTEmIR9qLV/Tc/HCaEymjzefcQz8KyeyrF65\n"
      + "y85v4qvlIHRpWKuPkretrw+mgGcRUAwTjug7AwFPgRBNSMRuhudkwiQ+Y6g9y5sU\n"
      + "iBy0z8zSeUId8P+P07Kg/BXMW4BoqNjD0UumIBOB8zj8bzPW5ctnpoMCgYEA901n\n"
      + "dvLf2NPQjqfcjLY9Y/wvzxM4dwanLj5DF/M71CKCPd+/9bzSJQCmHJbCoPEuTV6G\n"
      + "T/MXNi8BLLr11KybfWseizxoDXQikcPHiPt258P18hftArG0XQtIRb64uOsNTrgw\n"
      + "40P3ibYkwjguB3FHTZjGTAAW8tYYe+U4eeoLKuUCgYEAquWgAWwHJklCCm9Yyt97\n"
      + "RUoVZ6F79sNivD6EDDVPxZfjnuPnFTEaXq5NiejK8FI3/Lgffqr5krfEIc4BVH3i\n"
      + "TZelEestBMQaY1uUcEpXiKJ0S7J7H3ZaPOqHlL7IJKiGgqtzc9/BauK5mqBHmiht\n"
      + "E5yn7uXPstSEVOYPSo/7qmcCgYEAuKuRho6pP7Y0eEK7fEweHcrVPLHiqWdLcknG\n"
      + "Ol1FIQ0/6spqAywkVMNeR90Aq8ROSjI64/roK2sAWpGmP1FBr29NWLYcEWfW5Lip\n"
      + "CQ6W5U09HLJnJ2rh/9UL/CEGufe0cUM0JpG7iJd+bZYcMSyTDUv3UAuFF4Nutx4d\n"
      + "hVSTUE0CgYBcdLVogptc7q5y46zhXCAc3C3mGppHstriAoZ2I9jUXG2lgYYLYyQT\n"
      + "t6yW/VpSoAQz97ih7FU87JBoarm1iygfh9Bx/hnXXIS69qSDh8gRTuxB0C6wu9/o\n"
      + "n7NA6JhhMVoynkIF41rn+uaMqXAXa/cYKzp9kwuKJZKqJ7xUdzrwQQ==";
  private static final String FAKE_PASSWORD = "harbvcrtvoxqjfeuaqbtalcypoixyw";
  private static final String USERNAME = "generated-user";
  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";
  private static final String CERTIFICATE = CA; // self signed
  private static final String FINGER_PRINT = "Px23DxgJx1+P7gAtzV7S2/cvWyRDn7GfCRvx7VUkzoY";
  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);
  private static UUID credentialUuid;
  @Rule
  public final SpringMethodRule springMethodRule = new SpringMethodRule();
  @Parameterized.Parameter
  public TestParameterizer parametizer;
  @Autowired
  private WebApplicationContext webApplicationContext;
  @MockitoSpyBean
  private CredentialVersionDataService credentialVersionDataService;
  @MockitoBean
  private CurrentTimeProvider mockCurrentTimeProvider;
  @MockitoBean
  private PasswordCredentialGenerator passwordGenerator;
  @MockitoBean
  private CertificateGenerator certificateGenerator;
  @MockitoBean
  private SshGenerator sshGenerator;
  @MockitoBean
  private RsaGenerator rsaGenerator;
  @MockitoBean
  private UserGenerator userGenerator;
  @MockitoSpyBean
  private ObjectMapper objectMapper;
  @Autowired
  private Encryptor encryptor;
  @Autowired
  private CryptSaltFactory cryptSaltFactory;
  private MockMvc mockMvc;

  @Parameterized.Parameters(name = "{0}")
  public static Collection<Object> parameters() {
    credentialUuid = UUID.randomUUID();
    final Collection<Object> params = new ArrayList<>();

    final TestParameterizer passwordParameters = new TestParameterizer("password", "{\"exclude_number\": true}") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value", FAKE_PASSWORD);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) credential;
        assertThat(passwordCredential.getGenerationParameters().isExcludeNumber(), equalTo(true));
        assertThat(passwordCredential.getPassword(), equalTo(FAKE_PASSWORD));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {

        final StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();
        stringGenerationParameters.setExcludeNumber(true);

        PasswordCredentialVersion passwordCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
        passwordCredentialVersion.setEncryptor(encryptor);
        passwordCredentialVersion.setPasswordAndGenerationParameters(FAKE_PASSWORD, stringGenerationParameters);
        passwordCredentialVersion.setUuid(credentialUuid);
        passwordCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return passwordCredentialVersion;
      }
    };

    final TestParameterizer userParameterizer = new TestParameterizer("user", "{\"exclude_number\": true}") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value.username", USERNAME, "$.value.password", FAKE_PASSWORD);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final UserCredentialVersion userCredential = (UserCredentialVersion) credential;
        assertThat(userCredential.getGenerationParameters().isExcludeNumber(), equalTo(true));
        assertThat(userCredential.getUsername(), equalTo(USERNAME));
        assertThat(userCredential.getPassword(), equalTo(FAKE_PASSWORD));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {

        final StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();
        stringGenerationParameters.setExcludeNumber(true);

        UserCredentialVersion userCredentialVersion = new UserCredentialVersion(CREDENTIAL_NAME);
        userCredentialVersion.setEncryptor(encryptor);
        userCredentialVersion.setPassword(FAKE_PASSWORD);
        userCredentialVersion.setGenerationParameters(stringGenerationParameters);
        userCredentialVersion.setUsername(USERNAME);
        userCredentialVersion.setUuid(credentialUuid);
        userCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return userCredentialVersion;
      }
    };

    final TestParameterizer certificateParameterizer = new TestParameterizer("certificate",
      "{\"common_name\":\"example.com\",\"self_sign\":true}") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.certificate", CERTIFICATE,
          "$.value.private_key", CERTIFICATE_PRIVATE_KEY,
          "$.value.ca", CA);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credential;
        assertThat(certificateCredential.getCa(), equalTo(CA));
        assertThat(certificateCredential.getCertificate(), equalTo(CERTIFICATE));
        assertThat(certificateCredential.getPrivateKey(), equalTo(CERTIFICATE_PRIVATE_KEY));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        CertificateCredentialVersion certificateCredentialVersion = new CertificateCredentialVersion(CREDENTIAL_NAME);
        certificateCredentialVersion.setEncryptor(encryptor);
        certificateCredentialVersion.setCa(CA);
        certificateCredentialVersion.setCertificate(CERTIFICATE);
        certificateCredentialVersion.setPrivateKey(CERTIFICATE_PRIVATE_KEY);
        certificateCredentialVersion.setUuid(credentialUuid);
        certificateCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return certificateCredentialVersion;
      }
    };

    final TestParameterizer sshParameterizer = new TestParameterizer("ssh", "null") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.public_key", PUBLIC_KEY,
          "$.value.private_key", PRIVATE_KEY,
          "$.value.public_key_fingerprint", FINGER_PRINT);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final SshCredentialVersion sshCredential = (SshCredentialVersion) credential;
        assertThat(sshCredential.getPublicKey(), equalTo(PUBLIC_KEY));
        assertThat(sshCredential.getPrivateKey(), equalTo(PRIVATE_KEY));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        SshCredentialVersion sshCredentialVersion = new SshCredentialVersion(CREDENTIAL_NAME);
        sshCredentialVersion.setEncryptor(encryptor);
        sshCredentialVersion.setPrivateKey(PRIVATE_KEY);
        sshCredentialVersion.setPublicKey(PUBLIC_KEY);
        sshCredentialVersion.setUuid(credentialUuid);
        sshCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return sshCredentialVersion;
      }
    };

    final TestParameterizer rsaParameterizer = new TestParameterizer("rsa", "null") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value.public_key", RSA_PUBLIC_KEY,
          "$.value.private_key", RSA_PRIVATE_KEY);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credential;
        assertThat(rsaCredential.getPublicKey(), equalTo(RSA_PUBLIC_KEY));
        assertThat(rsaCredential.getPrivateKey(), equalTo(RSA_PRIVATE_KEY));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        RsaCredentialVersion rsaCredentialVersion = new RsaCredentialVersion(CREDENTIAL_NAME);
        rsaCredentialVersion.setEncryptor(encryptor);
        rsaCredentialVersion.setPrivateKey(RSA_PRIVATE_KEY);
        rsaCredentialVersion.setPublicKey(RSA_PUBLIC_KEY);
        rsaCredentialVersion.setUuid(credentialUuid);
        rsaCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return rsaCredentialVersion;
      }
    };

    params.add(passwordParameters);
    params.add(userParameterizer);
    params.add(certificateParameterizer);
    params.add(sshParameterizer);
    params.add(rsaParameterizer);

    return params;
  }

  @BeforeClass
  public static void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @Before
  public void setup() {
    final String fakeSalt = cryptSaltFactory.generateSalt(FAKE_PASSWORD);
    final Consumer<Long> fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    when(passwordGenerator.generateCredential(any(GenerationParameters.class)))
      .thenReturn(new StringCredentialValue(FAKE_PASSWORD));

    when(certificateGenerator.generateCredential(any(GenerationParameters.class)))
      .thenReturn(new CertificateCredentialValue(CA, CERTIFICATE, CERTIFICATE_PRIVATE_KEY, null, false, false, true, false));

    when(sshGenerator.generateCredential(any(GenerationParameters.class)))
      .thenReturn(new SshCredentialValue(PUBLIC_KEY, PRIVATE_KEY, null));

    when(rsaGenerator.generateCredential(any(GenerationParameters.class)))
      .thenReturn(new RsaCredentialValue(RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));

    when(userGenerator.generateCredential(any(GenerationParameters.class)))
      .thenReturn(new UserCredentialValue(USERNAME, FAKE_PASSWORD, fakeSalt));
  }


  @Test
  public void generatingACredential_validatesTheRequestBody() throws Exception {
    final MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    final DefaultCredentialGenerateRequest requestBody = mock(DefaultCredentialGenerateRequest.class);

    Mockito.doThrow(new ParameterizedValidationException(ErrorMessages.BAD_REQUEST)).when(requestBody).validate();
    doReturn(requestBody).when(objectMapper).readValue(anyString(), any(Class.class));

    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().json(
        "{\"error\":\"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}"));
  }

  @Test
  public void shouldAcceptAnyCasingForType() throws Exception {
    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType.toUpperCase() + "\"," +
        "\"parameters\":" + parametizer.generationParameters + "," +
        "\"overwrite\":" + false +
        "}");

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(parametizer.jsonAssertions())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.version_created_at", FROZEN_TIME.toString())
      );
  }

  @Test
  public void generatingANewCredential_shouldReturnGeneratedCredentialAndAskDataServiceToPersistTheCredential()
    throws Exception {
    final MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    final ResultActions response = mockMvc.perform(request);

    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final UUID uuid = argumentCaptor.getValue().getUuid();
    assertNotNull(uuid);

    response
      .andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.id", uuid.toString(),
        "$.version_created_at", FROZEN_TIME.toString()))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwrite_shouldGenerateANewCredential() throws Exception {
    beforeEachExistingCredential();
    final MockHttpServletRequestBuilder request = beforeEachOverwriteSetToTrue();

    final ResultActions response = mockMvc.perform(request);

    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final UUID uuid = argumentCaptor.getValue().getUuid();
    assertNotNull(uuid);

    response
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.id", uuid.toString(),
        "$.version_created_at", FROZEN_TIME.toString()));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwrite_shouldPersistTheNewCredential() throws Exception {
    beforeEachExistingCredential();
    final MockHttpServletRequestBuilder request = beforeEachOverwriteSetToTrue();

    mockMvc.perform(request);

    final CredentialVersion credentialVersion = credentialVersionDataService.findMostRecent(CREDENTIAL_NAME);
    parametizer.credentialAssertions(credentialVersion);
  }

  @Test
  public void generatingANewCredentialVersion_withOverwriteFalse_returnsThePreviousVersion_whenParametersAreTheSame() throws Exception {
    beforeEachExistingCredential();
    final MockHttpServletRequestBuilder request = beforeEachOverwriteSetToFalse();

    mockMvc.perform(request)
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.id", credentialUuid.toString(),
        "$.version_created_at", FROZEN_TIME.minusSeconds(1).toString()));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwriteFalse_doesNotPersistANewVersion_whenParametersAreTheSame() throws Exception {
    beforeEachExistingCredential();

    final MockHttpServletRequestBuilder request = beforeEachOverwriteSetToFalse();
    mockMvc.perform(request);

    verify(credentialVersionDataService, times(0)).save(any(CredentialVersion.class));
  }

  private MockHttpServletRequestBuilder createGenerateNewCredentialRequest() {
    return post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType + "\"," +
        "\"parameters\":" + parametizer.generationParameters + "," +
        "\"overwrite\":" + false +
        "}");
  }

  private void beforeEachExistingCredential() {
    CredentialVersion credentialVersion = parametizer.createCredential(encryptor);
    doReturn(Collections.singletonList(credentialVersion))
      .when(credentialVersionDataService)
      .findActiveByName(CREDENTIAL_NAME);
    doReturn(credentialVersion)
      .when(credentialVersionDataService)
      .findMostRecent(CREDENTIAL_NAME);
  }

  private MockHttpServletRequestBuilder beforeEachOverwriteSetToTrue() {
    return post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"" + parametizer.credentialType + "\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"parameters\":" + parametizer.generationParameters + "," +
        "  \"overwrite\":true" +
        "}");
  }

  private MockHttpServletRequestBuilder beforeEachOverwriteSetToFalse() {
    return post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"" + parametizer.credentialType + "\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"parameters\":" + parametizer.generationParameters + "," +
        "  \"overwrite\":false" +
        "}");
  }

  private static abstract class TestParameterizer {

    final String credentialType;
    final String generationParameters;

    TestParameterizer(final String credentialType, final String generationParameters) {
      super();
      this.credentialType = credentialType;
      this.generationParameters = generationParameters;
    }

    @Override
    public String toString() {
      return credentialType;
    }

    abstract ResultMatcher jsonAssertions();

    abstract void credentialAssertions(CredentialVersion credentialVersion);

    abstract CredentialVersion createCredential(Encryptor encryptor);
  }

}
