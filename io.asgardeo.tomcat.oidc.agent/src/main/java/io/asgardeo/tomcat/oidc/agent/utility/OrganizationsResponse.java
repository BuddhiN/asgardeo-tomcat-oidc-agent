package io.asgardeo.tomcat.oidc.agent.utility;

import java.util.List;

public class OrganizationsResponse {

    public List<Organization> getOrganizations() {
        return organizations;
    }

    @Override
    public String toString() {
        return "OrganizationsResponse{" +
                "organizations=" + organizations +
                '}';
    }

    public void setOrganizations(List<Organization> organizations) {
        this.organizations = organizations;
    }

    private List<Organization> organizations;

}
