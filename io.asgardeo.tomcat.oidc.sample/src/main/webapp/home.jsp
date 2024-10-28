<%--
  ~ Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="io.asgardeo.java.oidc.sdk.SSOAgentConstants" %>
<%@ page import="io.asgardeo.java.oidc.sdk.bean.SessionContext" %>
<%@ page import="io.asgardeo.java.oidc.sdk.bean.User" %>
<%@ page import="io.asgardeo.java.oidc.sdk.config.model.OIDCAgentConfig" %>
<%@ page import="io.asgardeo.tomcat.oidc.agent.utility.OrganizationsResponse" %>
<%@ page import="io.asgardeo.tomcat.oidc.agent.utility.Organization" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="net.minidev.json.JSONObject" %>
<%@ page import="com.nimbusds.jwt.SignedJWT" %>

<%
    final HttpSession currentSession = request.getSession(false);
    final SessionContext sessionContext = (SessionContext)
            currentSession.getAttribute(SSOAgentConstants.SESSION_CONTEXT);
    final String idToken = sessionContext.getIdToken();
    final String accessToken = sessionContext.getAccessToken();

    final OrganizationsResponse orgResponse = (OrganizationsResponse)currentSession.getAttribute("data");
    System.out.println("org set ---- " + orgResponse.toString());
    List<Organization> orgList = orgResponse.getOrganizations();

    String scopes = "";

    ServletContext servletContext = getServletContext();
    if (servletContext.getAttribute(SSOAgentConstants.CONFIG_BEAN_NAME) != null) {
        OIDCAgentConfig oidcAgentConfig = (OIDCAgentConfig) servletContext.getAttribute(SSOAgentConstants.CONFIG_BEAN_NAME);
        scopes = oidcAgentConfig.getScope().toString();
    }

    SignedJWT signedJWTIdToken = SignedJWT.parse(idToken);
    String payload = signedJWTIdToken.getJWTClaimsSet().toString();
    String header = signedJWTIdToken.getHeader().toString();

    String name = null;
    Map<String, Object> customClaimValueMap = new HashMap<>();

    if (idToken != null) {
        final User user = sessionContext.getUser();
        customClaimValueMap = user.getAttributes();
        name = user.getSubject();
    }
%>

<html>
<head>
    <meta charset="UTF-8">
    <title>Home</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" type="text/css" href="theme.css">
</head>
<body>

    <div class="ui two column centered grid">
        <div class="column center aligned">
            <img src="images/logo-dark.svg" class="logo-image">
        </div>
        <div class="container">
            <div class="header-title">
                <h1>
                    Java-Based OIDC Authentication Sample<br> (OIDC - Authorization Code Grant)
                </h1>
            </div>

            <div class="content">
                <form id="orgForm" action="suborg.jsp" method="post">
                    <input type="hidden" id="hiddenOrgId" name="hiddenOrgId">
                    <%
                        for (int i = 0; i < orgList.size(); i++) {
                            Organization organization = orgList.get(i);
                    %>
                    <div class="element-padding">
                        <button class="btn primary orgBtn" type="button" id="'<%=organization.getId() %>'">
                        <%=organization.getName() %>
                        </button>
                    </div>
                    <%
                        }
                    %>

                </form>
                <h3>
                    Your app has successfully connected with Asgardeo and the user is logged in.<br>
                    This is the user information returned from Asgardeo.
                </h3>
                <h2>Authentication Response</h2>
                <div class="json">
                    <div id="authentication-response" class="json-container"></div>
                </div>
                <h2 class="mb-0 mt-4">ID token</h2>

                <div class="row">
                    <div class="column">
                        <h5><b>Encoded</b></h5>
                        <div class="code">
                            <code>
                                <span class="id-token-0" id="id-token-0"></span>.<span class="id-token-1" id="id-token-1"></span>.<span class="id-token-2" id="id-token-2"></span>
                            </code>
                        </div>
                    </div>
                    <div class="column">
                        <div class="json">
                            <h5><b>Decoded:</b> Header</h5>
                            <div id="id-token-header" class="json-container"></div>
                        </div>

                        <div class="json">
                            <h5><b>Decoded:</b> Payload</h5>
                            <div id="id-token-payload" class="json-container"></div>
                        </div>

                        <div class="json">
                            <h5>Signature</h5>
                            <div class="code">
                                <code>
                                    HMACSHA256(
                                        <br />
                                        &nbsp;&nbsp;<span class="id-token-0">base64UrlEncode(
                                            <span class="id-token-1">header</span>)</span> + "." + <br />
                                        &nbsp;&nbsp;<span class="id-token-0">base64UrlEncode(
                                            <span class="id-token-1">payload</span>)</span>,&nbsp;
                                        <span class="id-token-1">your-256-bit-secret</span> <br />
                                    );
                                </code>
                            </div>
                        </div>
                    </div>
                </div>
                <form action="logout" method="GET">
                    <div class="element-padding">
                        <button class="btn primary" type="submit">Logout</button>
                    </div>
                </form>
            </div>
        </div>
        <img src="images/footer.png" class="footer-image">
    </div>
    <script src="https://unpkg.com/json-formatter-js@latest/dist/json-formatter.umd.js"></script>

    <script>
        var payload = '<%=payload %>';
        var header = '<%=header %>';
        var idToken = '<%=idToken %>';
        var name = '<%=name%>';
        var scope = '<%=scopes%>';
        const scopeList = scope.split(" ");
        let responses = {
            "allowedScopes" : scopeList,
            "username" : name
        }
        var payloadObject = JSON.parse(payload);
        var headerObject = JSON.parse(header);
        var responseObject = JSON.parse(JSON.stringify(responses));

        const idTokenSplit = idToken.split(".");

        var responseViewBox = document.getElementById("authentication-response")
        var payloadViewBox = document.getElementById("id-token-payload");
        var headerViewBox = document.getElementById("id-token-header");

        responseViewBox.innerHTML = "";
        payloadViewBox.innerHTML = "";
        headerViewBox.innerHTML = "";

        document.getElementById("id-token-0").innerHTML = idTokenSplit[0];
        document.getElementById("id-token-1").innerHTML = idTokenSplit[1];
        document.getElementById("id-token-2").innerHTML = idTokenSplit[2];

        var formattedResponse = new JSONFormatter(responseObject, 1, { theme: "dark" })
        var formattedPayloadResponse = new JSONFormatter(payloadObject, 1, { theme: "dark" });
        var formattedHeaderResponse = new JSONFormatter(headerObject, 1, { theme: "dark" });

        responseViewBox.appendChild(formattedResponse.render());
        payloadViewBox.appendChild(formattedPayloadResponse.render());
        headerViewBox.appendChild(formattedHeaderResponse.render());

        const buttons = document.querySelectorAll(".orgBtn");

            buttons.forEach(button => {
                button.addEventListener("click", function() {
                    // Access the id of the clicked button
                    console.log("Clicked button ID:", this.id);
                    document.getElementById("hiddenOrgId").value = this.id;

                    console.log("hidden id === ", document.getElementById("hiddenOrgId").value);
                    document.getElementById("orgForm").submit();
                });
            });
    </script>
</body>
</html>
