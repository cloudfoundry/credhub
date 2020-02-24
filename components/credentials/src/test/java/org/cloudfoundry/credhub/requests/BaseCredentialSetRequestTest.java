package org.cloudfoundry.credhub.requests;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeChecked;

@RunWith(JUnit4.class)
public class BaseCredentialSetRequestTest {
  @Test(expected = JsonMappingException.class)
  public void whenTypeIsNotSet_throwsException() throws IOException {
    final String json = "{" +
                        "\"name\":\"some-name\"," +
                        "\"value\":\"some-value\"," +
                        "\"overwrite\":true" +
                        "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }


  @Test(expected = InvalidTypeIdException.class)
  public void whenTypeIsEmptyString_throwsException() throws IOException {
    final String json = "{" +
                        "\"name\":\"some-name\"," +
                        "\"type\":\"\"," +
                        "\"value\":\"some-value\"," +
                        "\"overwrite\":true" +
                        "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }

  @Test(expected = InvalidTypeIdException.class)
  public void whenTypeIsUnknown_throwsException() throws IOException {
    final String json = "{" +
                        "\"name\":\"some-name\"," +
                        "\"type\":\"moose\"," +
                        "\"value\":\"some-value\"," +
                        "\"overwrite\":true" +
                        "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }

  @Test(expected = UnrecognizedPropertyException.class)
  public void whenValueHasUnknownField_throwsException() throws IOException {
    final String json = "{\n"
                        + "  \"name\": \"/example/certificate\",\n"
                        + "  \"type\": \"certificate\",\n"
                        + "  \"metadata\": \"hello\",\n"
                        + "  \"value\": {"
                        + "    \"foo\": \"\""
                        + "  }"
                        + "}";
    deserializeChecked(json, BaseCredentialSetRequest.class);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void whenMetadataExceeds7000Characters_throwsException() throws IOException {
    final String json = "{\n" +
                        "  \"name\": \"test\",\n" +
                        "  \"type\": \"value\",\n" +
                        "  \"value\": \"some value\",\n" +
                        "  \"metadata\": {\n" +
                        "    \"data\": [\n" +
                        "      {\n" +
                        "        \"_id\": \"5e5692777f6995017fc23e0f\",\n" +
                        "        \"index\": 0,\n" +
                        "        \"guid\": \"d649bf3d-6426-4e64-8b61-3b29189bd3ff\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$3,707.66\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 40,\n" +
                        "        \"eyeColor\": \"brown\",\n" +
                        "        \"name\": \"Blanche Clements\",\n" +
                        "        \"gender\": \"female\",\n" +
                        "        \"company\": \"GEEKUS\",\n" +
                        "        \"email\": \"blancheclements@geekus.com\",\n" +
                        "        \"phone\": \"+1 (911) 583-2011\",\n" +
                        "        \"address\": \"323 Hampton Avenue, Belva, Kansas, 5131\",\n" +
                        "        \"about\": \"Pariatur adipisicing minim voluptate est exercitation. Elit in cupidatat anim aliquip sit sint consectetur pariatur ullamco quis sit. Laboris est aute nostrud cillum ad esse eiusmod est minim sit. Esse sunt dolor velit aliquip. Fugiat aliqua irure cupidatat nulla exercitation qui amet proident adipisicing nisi fugiat cillum. Id mollit ullamco do pariatur culpa ex anim consectetur fugiat mollit anim consequat.\\r\\n\",\n" +
                        "        \"registered\": \"2017-07-01T11:47:19 +04:00\",\n" +
                        "        \"latitude\": -27.533201,\n" +
                        "        \"longitude\": -39.913216,\n" +
                        "        \"tags\": [\n" +
                        "          \"incididunt\",\n" +
                        "          \"ea\",\n" +
                        "          \"culpa\",\n" +
                        "          \"pariatur\",\n" +
                        "          \"minim\",\n" +
                        "          \"excepteur\",\n" +
                        "          \"eiusmod\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Banks Dalton\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Holly Dickerson\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Valerie Howard\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Blanche Clements! You have 10 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"apple\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e56927791894b42d22a27a7\",\n" +
                        "        \"index\": 1,\n" +
                        "        \"guid\": \"ac7474c9-3534-4cb7-b465-8a67dd439260\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$3,679.85\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 29,\n" +
                        "        \"eyeColor\": \"blue\",\n" +
                        "        \"name\": \"Webster Simmons\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"LETPRO\",\n" +
                        "        \"email\": \"webstersimmons@letpro.com\",\n" +
                        "        \"phone\": \"+1 (904) 532-3958\",\n" +
                        "        \"address\": \"617 Roosevelt Court, Maybell, New Jersey, 6265\",\n" +
                        "        \"about\": \"Enim qui nisi cupidatat deserunt proident nostrud tempor minim incididunt labore in eiusmod consectetur ex. Aliquip velit et ad dolor excepteur irure ipsum aliqua. Ea occaecat ad cupidatat mollit eu in reprehenderit mollit sunt nulla enim ad voluptate laboris. Amet ea irure aliqua reprehenderit ad aliqua cupidatat laborum duis quis id sint ea ipsum.\\r\\n\",\n" +
                        "        \"registered\": \"2017-11-14T04:35:12 +05:00\",\n" +
                        "        \"latitude\": 46.00308,\n" +
                        "        \"longitude\": 175.232947,\n" +
                        "        \"tags\": [\n" +
                        "          \"reprehenderit\",\n" +
                        "          \"excepteur\",\n" +
                        "          \"qui\",\n" +
                        "          \"labore\",\n" +
                        "          \"veniam\",\n" +
                        "          \"dolor\",\n" +
                        "          \"nulla\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Selena Cooper\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Montgomery Porter\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Mullins Walton\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Webster Simmons! You have 10 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"banana\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277912409f5a0348418\",\n" +
                        "        \"index\": 2,\n" +
                        "        \"guid\": \"701a4cdc-1804-4f06-b54d-f05f39736345\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$2,820.98\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 33,\n" +
                        "        \"eyeColor\": \"brown\",\n" +
                        "        \"name\": \"Farley Sosa\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"ORBIN\",\n" +
                        "        \"email\": \"farleysosa@orbin.com\",\n" +
                        "        \"phone\": \"+1 (994) 410-3948\",\n" +
                        "        \"address\": \"630 Irving Place, Rutherford, Palau, 5980\",\n" +
                        "        \"about\": \"Incididunt et excepteur voluptate eiusmod cillum anim voluptate dolor consectetur Lorem ut non veniam. Enim do irure ipsum deserunt esse magna labore nulla aute reprehenderit culpa irure. Occaecat incididunt incididunt occaecat incididunt elit id consectetur occaecat sunt eu fugiat quis. Consequat culpa ipsum in velit culpa deserunt mollit tempor exercitation nulla. Qui sit eiusmod nisi et.\\r\\n\",\n" +
                        "        \"registered\": \"2016-09-03T06:52:28 +04:00\",\n" +
                        "        \"latitude\": 1.699416,\n" +
                        "        \"longitude\": -150.063417,\n" +
                        "        \"tags\": [\n" +
                        "          \"Lorem\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"mollit\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"sint\",\n" +
                        "          \"incididunt\",\n" +
                        "          \"aliquip\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Elliott Randolph\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Tracey Chen\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Rivera Jensen\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Farley Sosa! You have 8 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"apple\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277912409f5a0348418\",\n" +
                        "        \"index\": 2,\n" +
                        "        \"guid\": \"701a4cdc-1804-4f06-b54d-f05f39736345\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$2,820.98\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 33,\n" +
                        "        \"eyeColor\": \"brown\",\n" +
                        "        \"name\": \"Farley Sosa\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"ORBIN\",\n" +
                        "        \"email\": \"farleysosa@orbin.com\",\n" +
                        "        \"phone\": \"+1 (994) 410-3948\",\n" +
                        "        \"address\": \"630 Irving Place, Rutherford, Palau, 5980\",\n" +
                        "        \"about\": \"Incididunt et excepteur voluptate eiusmod cillum anim voluptate dolor consectetur Lorem ut non veniam. Enim do irure ipsum deserunt esse magna labore nulla aute reprehenderit culpa irure. Occaecat incididunt incididunt occaecat incididunt elit id consectetur occaecat sunt eu fugiat quis. Consequat culpa ipsum in velit culpa deserunt mollit tempor exercitation nulla. Qui sit eiusmod nisi et.\\r\\n\",\n" +
                        "        \"registered\": \"2016-09-03T06:52:28 +04:00\",\n" +
                        "        \"latitude\": 1.699416,\n" +
                        "        \"longitude\": -150.063417,\n" +
                        "        \"tags\": [\n" +
                        "          \"Lorem\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"mollit\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"sint\",\n" +
                        "          \"incididunt\",\n" +
                        "          \"aliquip\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Elliott Randolph\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Tracey Chen\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Rivera Jensen\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Farley Sosa! You have 8 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"apple\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277912409f5a0348418\",\n" +
                        "        \"index\": 2,\n" +
                        "        \"guid\": \"701a4cdc-1804-4f06-b54d-f05f39736345\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$2,820.98\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 33,\n" +
                        "        \"eyeColor\": \"brown\",\n" +
                        "        \"name\": \"Farley Sosa\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"ORBIN\",\n" +
                        "        \"email\": \"farleysosa@orbin.com\",\n" +
                        "        \"phone\": \"+1 (994) 410-3948\",\n" +
                        "        \"address\": \"630 Irving Place, Rutherford, Palau, 5980\",\n" +
                        "        \"about\": \"Incididunt et excepteur voluptate eiusmod cillum anim voluptate dolor consectetur Lorem ut non veniam. Enim do irure ipsum deserunt esse magna labore nulla aute reprehenderit culpa irure. Occaecat incididunt incididunt occaecat incididunt elit id consectetur occaecat sunt eu fugiat quis. Consequat culpa ipsum in velit culpa deserunt mollit tempor exercitation nulla. Qui sit eiusmod nisi et.\\r\\n\",\n" +
                        "        \"registered\": \"2016-09-03T06:52:28 +04:00\",\n" +
                        "        \"latitude\": 1.699416,\n" +
                        "        \"longitude\": -150.063417,\n" +
                        "        \"tags\": [\n" +
                        "          \"Lorem\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"mollit\",\n" +
                        "          \"voluptate\",\n" +
                        "          \"sint\",\n" +
                        "          \"incididunt\",\n" +
                        "          \"aliquip\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Elliott Randolph\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Tracey Chen\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Rivera Jensen\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Farley Sosa! You have 8 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"apple\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277497ae2331e5dbed8\",\n" +
                        "        \"index\": 3,\n" +
                        "        \"guid\": \"25e98828-0385-4e30-b32a-67547d01a166\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$3,385.12\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 29,\n" +
                        "        \"eyeColor\": \"brown\",\n" +
                        "        \"name\": \"Warner Snider\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"VERBUS\",\n" +
                        "        \"email\": \"warnersnider@verbus.com\",\n" +
                        "        \"phone\": \"+1 (811) 407-3601\",\n" +
                        "        \"address\": \"324 Kay Court, Levant, Montana, 8657\",\n" +
                        "        \"about\": \"Ea voluptate adipisicing et culpa reprehenderit labore do dolore. Do ipsum adipisicing et est proident pariatur nisi aute. Dolor in exercitation cupidatat incididunt non.\\r\\n\",\n" +
                        "        \"registered\": \"2019-02-09T08:56:11 +05:00\",\n" +
                        "        \"latitude\": -76.41795,\n" +
                        "        \"longitude\": 128.314009,\n" +
                        "        \"tags\": [\n" +
                        "          \"do\",\n" +
                        "          \"culpa\",\n" +
                        "          \"nulla\",\n" +
                        "          \"exercitation\",\n" +
                        "          \"consequat\",\n" +
                        "          \"aliquip\",\n" +
                        "          \"mollit\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Anna Parrish\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Wolf House\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Weeks Palmer\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Warner Snider! You have 2 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"strawberry\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277d31960b2ef9ea5bc\",\n" +
                        "        \"index\": 4,\n" +
                        "        \"guid\": \"7433f960-5bf4-4d73-8de2-6618e6430c3b\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$1,715.93\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 21,\n" +
                        "        \"eyeColor\": \"blue\",\n" +
                        "        \"name\": \"Andrea Dunn\",\n" +
                        "        \"gender\": \"female\",\n" +
                        "        \"company\": \"MANUFACT\",\n" +
                        "        \"email\": \"andreadunn@manufact.com\",\n" +
                        "        \"phone\": \"+1 (800) 561-2309\",\n" +
                        "        \"address\": \"906 Clarkson Avenue, Castleton, Colorado, 7878\",\n" +
                        "        \"about\": \"Est non sunt pariatur ex Lorem labore commodo amet ut. Cillum nulla duis minim quis et. Labore consectetur exercitation culpa incididunt excepteur sunt quis labore consequat et non excepteur fugiat ullamco. Aute labore duis deserunt irure adipisicing eu sint voluptate laboris sint. Mollit aute do pariatur aute do mollit proident do minim fugiat. Enim non tempor consectetur ipsum minim ex ut ea ipsum.\\r\\n\",\n" +
                        "        \"registered\": \"2015-03-12T09:06:47 +04:00\",\n" +
                        "        \"latitude\": -40.200843,\n" +
                        "        \"longitude\": -97.902076,\n" +
                        "        \"tags\": [\n" +
                        "          \"officia\",\n" +
                        "          \"cupidatat\",\n" +
                        "          \"sunt\",\n" +
                        "          \"incididunt\",\n" +
                        "          \"labore\",\n" +
                        "          \"culpa\",\n" +
                        "          \"anim\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Renee Bolton\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Huber Lyons\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Hooper Santana\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Andrea Dunn! You have 7 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"banana\"\n" +
                        "      },\n" +
                        "      {\n" +
                        "        \"_id\": \"5e569277c5e093fcb61e2f04\",\n" +
                        "        \"index\": 5,\n" +
                        "        \"guid\": \"59097b4c-54ab-4bd8-a958-0406c7b42dc2\",\n" +
                        "        \"isActive\": true,\n" +
                        "        \"balance\": \"$3,112.45\",\n" +
                        "        \"picture\": \"http://placehold.it/32x32\",\n" +
                        "        \"age\": 40,\n" +
                        "        \"eyeColor\": \"blue\",\n" +
                        "        \"name\": \"Joyner Dale\",\n" +
                        "        \"gender\": \"male\",\n" +
                        "        \"company\": \"NETBOOK\",\n" +
                        "        \"email\": \"joynerdale@netbook.com\",\n" +
                        "        \"phone\": \"+1 (935) 565-2280\",\n" +
                        "        \"address\": \"619 Beaumont Street, Homestead, Indiana, 2022\",\n" +
                        "        \"about\": \"Voluptate nisi amet do Lorem occaecat nostrud excepteur sit qui elit ullamco voluptate. Ullamco occaecat ut ad ad occaecat. Officia amet est voluptate velit mollit et laboris esse exercitation. Aliqua elit ea elit ex. Consectetur duis quis do exercitation dolor labore. Sint id dolor incididunt consequat consectetur adipisicing consectetur. Ex fugiat tempor pariatur ex sint fugiat sit commodo sint.\\r\\n\",\n" +
                        "        \"registered\": \"2016-10-13T08:27:44 +04:00\",\n" +
                        "        \"latitude\": -41.281882,\n" +
                        "        \"longitude\": -162.703305,\n" +
                        "        \"tags\": [\n" +
                        "          \"proident\",\n" +
                        "          \"pariatur\",\n" +
                        "          \"labore\",\n" +
                        "          \"occaecat\",\n" +
                        "          \"consectetur\",\n" +
                        "          \"reprehenderit\",\n" +
                        "          \"cillum\"\n" +
                        "        ],\n" +
                        "        \"friends\": [\n" +
                        "          {\n" +
                        "            \"id\": 0,\n" +
                        "            \"name\": \"Alexandria Lucas\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 1,\n" +
                        "            \"name\": \"Nicole Perkins\"\n" +
                        "          },\n" +
                        "          {\n" +
                        "            \"id\": 2,\n" +
                        "            \"name\": \"Kayla Mays\"\n" +
                        "          }\n" +
                        "        ],\n" +
                        "        \"greeting\": \"Hello, Joyner Dale! You have 4 unread messages.\",\n" +
                        "        \"favoriteFruit\": \"strawberry\"\n" +
                        "      }\n" +
                        "    ]\n" +
                        "  }\n" +
                        "}";
    BaseCredentialRequest baseCredentialSetRequest = deserializeChecked(json, BaseCredentialSetRequest.class);
    baseCredentialSetRequest.validate();
  }
}
