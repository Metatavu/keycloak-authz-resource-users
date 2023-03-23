package fi.metatavu.keycloak.authz;

import java.util.List;

public class AuthzResourceUsersAccessRequest {

  private List<String> userIds;

  private List<String> resourceIds;

  private List<String> scopes;

  public List<String> getUserIds() {
    return userIds;
  }

  public void setUserIds(List<String> userIds) {
    this.userIds = userIds;
  }

  public List<String> getResourceIds() {
    return resourceIds;
  }

  public void setResourceIds(List<String> resourceIds) {
    this.resourceIds = resourceIds;
  }

  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(List<String> scopes) {
    this.scopes = scopes;
  }
}
