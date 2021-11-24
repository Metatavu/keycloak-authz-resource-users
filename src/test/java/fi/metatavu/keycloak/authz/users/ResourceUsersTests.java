package fi.metatavu.keycloak.authz.users;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;
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
  private KeycloakContainer keycloak = new KeycloakContainer("jboss/keycloak:15.0.2")
    .withProviderClassesFrom("target/classes")
    .withRealmImportFile("kc.json");

  /**
   * Asserts that resource 1 is allowed only for users in group 1 via group policy
   */
  @Test
  void testResource1Users() {
    assertTrue(keycloak.isRunning());

    given()
      .baseUri(keycloak.getAuthServerUrl())
      .when()
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_1_ID))
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
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_2_ID))
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
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_3_ID))
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
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_4_ID))
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
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_5_ID))
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
      .get(String.format("/realms/test/authz-resource-users/clients/e5ad8dc7-67f4-4d58-baab-b7162c53bced/resource/%s/users", TestConsts.RESOURCE_6_ID))
      .then()
      .assertThat()
      .statusCode(200)
      .contentType(ContentType.JSON)
      .body("size()", equalTo(1))
      .body("id", hasItems(TestConsts.USER_1_GROUP_4_ID));
  }

}