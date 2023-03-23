package fi.metatavu.keycloak.authz;

import java.util.List;

public class AuthzResourceUserAccessResponse {
  
  public AuthzResourceUserAccessResponse() {}

  public AuthzResourceUserAccessResponse(String userId, String resourceId, List<String> scopes) {
    this.userId = userId;
    this.resourceId = resourceId;
    this.scopes = scopes;
  }

  private String userId;

  private String resourceId;

  private List<String> scopes;
 
  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getResourceId() {
    return resourceId;
  }

  public void setResourceId(String resourceId) {
    this.resourceId = resourceId;
  }
  
  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(List<String> scopes) {
    this.scopes = scopes;
  }
}
