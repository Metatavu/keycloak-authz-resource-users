package fi.metatavu.keycloak.authz.users;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessTokenResponse;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.*;
import static io.restassured.RestAssured.*;
import static org.hamcrest.Matchers.*;

/**
 * Tests for authz resource users endpoint
 */
@Testcontainers
class ResourceUsersTests {

  @Container
  private static final KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:17.0.1")
    .withProviderClassesFrom("target/classes")
    .withRealmImportFile("kc.json")
    .withFeaturesEnabled("upload-scripts");

  /**
   * Asserts that resource 1 is allowed only for users in group 1 via group policy
   */
  @Test
  void testResource1Users() {
    assertTrue(keycloak.isRunning());
    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_1_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS));
  }

  /**
   * Asserts that resource 2 is not allowed for anyone
   */
  @Test
  void testResource2Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_2_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .body("size()", equalTo(0));
  }

  /**
   * Asserts that resource 3 is allowed only for users in group 3 via role policy
   */
  @Test
  void testResource3Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_3_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_3_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_3_USER_IDS));
  }

  /**
   * Asserts that resource 4 is allowed only for user 1 in group 4 via user policy and group 2 via type policy
   */
  @Test
  void testResource4Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_4_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_2_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_2_USER_IDS));
  }

  /**
   * Asserts that resource 4 is allowed only for group 2 via type policy
   */
  @Test
  void testResource5Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_5_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_2_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_2_USER_IDS));
  }

  /**
   * Asserts that resource 6 is allowed only for user 1 in group 4 via user policy
   */
  @Test
  void testResource6Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_6_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(1))
      .body("id", hasItems(TestConsts.USER_1_GROUP_4_ID));
  }

  /**
   * Asserts that resource 6 is allowed only for user 1 in group 4 via user policy
   */
  @Test
  void testSearchUsers() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("search", "user-1.group-1@example.com")
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(1))
      .body("id", hasItems(TestConsts.USER_1_GROUP_1_ID));
  }

  /**
   * Asserts that user does not have permission to access resource users
   */
  @Test
  void testResourceUsersForbidden() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getUserAccessToken()))
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(403);
  }

  /**
   * Asserts that user does not have permission to access resource users
   */
  @Test
  void testResourceUsersUnauthorized() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(401);
  }

  /**
   * Asserts that resource 1 is allowed only for users in group 1 via group policy
   */
  @Test
  void testResourceFirstAndMax() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("first", 0)
      .queryParam("max", 5)
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(5))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS[0], TestConsts.GROUP_1_USER_IDS[1], TestConsts.GROUP_1_USER_IDS[2], TestConsts.GROUP_1_USER_IDS[3], TestConsts.GROUP_1_USER_IDS[4]));

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("first", 1)
      .queryParam("max", 1)
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(1))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS[1]));

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("first", 9)
      .queryParam("max", 100)
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(1))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS[9]));
  }

  /**
   * Asserts that scoped resource 1 has:
   *
   * - access scope permitted to group 1 users
   * - manage scope permitted to group 2 users
   * - using both scopes returns users of both groups
   */
  @Test
  void testScopedResource1Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("scopes", "access")
      .get(getResourceUsersUrl(TestConsts.SCOPED_RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_1_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS));

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("scopes", "manage")
      .get(getResourceUsersUrl(TestConsts.SCOPED_RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_2_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_2_USER_IDS));

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("scopes", "access", "manage")
      .get(getResourceUsersUrl(TestConsts.SCOPED_RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(TestConsts.GROUP_1_USER_IDS.length + TestConsts.GROUP_2_USER_IDS.length))
      .body("id", hasItems(TestConsts.GROUP_1_USER_IDS))
      .body("id", hasItems(TestConsts.GROUP_2_USER_IDS));
  }

  /**
   * Asserts that invalid scope will end up in bad request
   */
  @Test
  void testInvalidScoped() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("scopes", "invalid")
      .get(getResourceUsersUrl(TestConsts.SCOPED_RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(400);
  }

  /**
   * Asserts that querying non scoped resource with scope yields bad request
   */
  @Test
  void testResource1WithScope() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .queryParam("scopes", "manage")
      .get(getResourceUsersUrl(TestConsts.RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(400);
  }
  /**
   * Asserts that querying scoped resource without scope results in empty result
   */
  @Test
  void testScopedResource1WithoutScopes() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .header("Authorization", String.format("Bearer %s", getAdminAccessToken()))
      .get(getResourceUsersUrl(TestConsts.SCOPED_RESOURCE_1_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(0));
  }

  /**
   * Returns resource users URL for given resource id
   *
   * @param resourceId resource id
   * @return resource users URL
   */
  private String getResourceUsersUrl(String resourceId) {
    return String.format("realms/%s/authz-resource-users/clients/%s/resource/%s/users",
      TestConsts.REALM,
      TestConsts.RESOURCE_SERVER_ID,
      resourceId
    );
  }

  /**
   * Returns access token for admin
   *
   * @return access token
   */
  private String getAdminAccessToken() {
    return getAccessToken(
      TestConsts.REALM,
      TestConsts.CLIENT_ID,
      TestConsts.CLIENT_SECRET,
      TestConsts.ADMIN_USERNAME,
      TestConsts.ADMIN_PASSWORD
    );
  }

  /**
   * Returns access token for user
   *
   * @return access token
   */
  private String getUserAccessToken() {
    return getAccessToken(
      TestConsts.REALM,
      TestConsts.CLIENT_ID,
      TestConsts.CLIENT_SECRET,
      TestConsts.USER_USERNAME,
      TestConsts.USER_PASSWORD
    );
  }

  /**
   * Returns access token for given user
   *
   * @param realm realm
   * @param clientId client id
   * @param clientSecret client secret
   * @param username username
   * @param password password
   * @return access token
   */
  private String getAccessToken(String realm, String clientId, String clientSecret, String username, String password) {
    AccessTokenResponse response = given()
      .baseUri(keycloak.getAuthServerUrl())
      .param("client_id", clientId)
      .param("grant_type", "password")
      .param("username", username)
      .param("password", password)
      .param("client_secret", clientSecret)
      .post(String.format("%srealms/%s/protocol/openid-connect/token", keycloak.getAuthServerUrl(), realm))
      .then()
      .assertThat()
      .statusCode(200)
      .extract()
      .body()
      .as(AccessTokenResponse.class);

    return response.getToken();
  }

}