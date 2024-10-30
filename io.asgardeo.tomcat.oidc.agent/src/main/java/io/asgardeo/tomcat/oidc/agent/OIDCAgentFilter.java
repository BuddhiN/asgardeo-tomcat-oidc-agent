/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.asgardeo.tomcat.oidc.agent;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import io.asgardeo.java.oidc.sdk.HTTPSessionBasedOIDCProcessor;
import io.asgardeo.java.oidc.sdk.SSOAgentConstants;
import io.asgardeo.java.oidc.sdk.bean.RequestContext;
import io.asgardeo.java.oidc.sdk.bean.SessionContext;
import io.asgardeo.java.oidc.sdk.config.model.OIDCAgentConfig;
import io.asgardeo.java.oidc.sdk.exception.SSOAgentClientException;
import io.asgardeo.java.oidc.sdk.exception.SSOAgentException;
import io.asgardeo.java.oidc.sdk.exception.SSOAgentServerException;
import io.asgardeo.java.oidc.sdk.request.OIDCRequestResolver;
import io.asgardeo.tomcat.oidc.agent.utility.Organization;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import io.asgardeo.tomcat.oidc.agent.utility.OrganizationsResponse;
import io.asgardeo.tomcat.oidc.agent.utility.TokenPayload;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * OIDCAgentFilter is the Filter class responsible for building
 * requests and handling responses for authentication, SLO and session
 * management for the OpenID Connect flows, using the io-asgardeo-oidc-sdk.
 * It is an implementation of the base class, {@link Filter}.
 * OIDCAgentFilter verifies if:
 * <ul>
 * <li>The request is a URL to skip
 * <li>The request is a Logout request
 * <li>The request is already authenticated
 * </ul>
 * <p>
 * and build and send the request, handle the response,
 * or forward the request accordingly.
 */
public class OIDCAgentFilter implements Filter {

    private static final Logger logger = LogManager.getLogger(OIDCAgentFilter.class);

    protected FilterConfig filterConfig = null;
    OIDCAgentConfig oidcAgentConfig;
    HTTPSessionBasedOIDCProcessor oidcManager;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        this.filterConfig = filterConfig;
        ServletContext servletContext = filterConfig.getServletContext();
        if (servletContext.getAttribute(SSOAgentConstants.CONFIG_BEAN_NAME) instanceof OIDCAgentConfig) {
            this.oidcAgentConfig = (OIDCAgentConfig) servletContext.getAttribute(SSOAgentConstants.CONFIG_BEAN_NAME);
        }
        try {
            this.oidcManager = new HTTPSessionBasedOIDCProcessor(oidcAgentConfig);
        } catch (SSOAgentClientException e) {
            throw new SSOAgentException(e.getMessage(), e);
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        /*String orgId = request.getParameter("hiddenOrgId");

        if (orgId != null) {
            String endpoint = "https://localhost:9443/oauth2/token"; // todo:fetch this from config property file
            String token = jsonToAccessToken(switchToSubOrg(endpoint, request, orgId));
            System.out.println("sub org token ******* " + token);
            return;
        }*/

        OIDCRequestResolver requestResolver = new OIDCRequestResolver(request, oidcAgentConfig);

        if (requestResolver.isSkipURI()) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (requestResolver.isLogoutURL()) {
            try {
                oidcManager.logout(request, response);
            } catch (SSOAgentException e) {
                handleException(request, response, e);
            }
            return;
        }

        if (requestResolver.isCallbackResponse()) {
            RequestContext requestContext = getRequestContext(request);
            if (requestContext == null) {
                handleException(request, response, new SSOAgentServerException("Request context is null."));
                return;
            }

            try {
                oidcManager.handleOIDCCallback(request, response);
            } catch (SSOAgentException e) {
                handleException(request, response, e);
                return;
            }
            // Check for logout scenario.
            if (requestResolver.isLogout()) {
                response.sendRedirect(oidcAgentConfig.getIndexPage());
                return;
            }

            String homePage = resolveTargetPage(request, requestContext);
            if (logger.isDebugEnabled()) {
                logger.debug("Redirection home page is set to " + homePage);
            }
            if (StringUtils.isBlank(homePage)) {
                handleException(request, response, new SSOAgentClientException("Redirection target is null."));
                return;
            }

            String endpointUrl = "https://localhost:9443/api/users/v1/me/organizations"; //todo:move this out
            String apiResponse = fetchSubOrganizations(endpointUrl, request);

            assert apiResponse != null;

            Gson gson = new Gson();
            OrganizationsResponse organizationsResponse = gson.fromJson(apiResponse, OrganizationsResponse.class);

            /*for(Organization organization : organizationsResponse.getOrganizations()) {
                organization.getName()
            }*/

            Organization organization = organizationsResponse.getOrganizations().get(0); //todo:select the correct org

            String jwtToken = getAccessToken(request);
            String orgNameClaim = null;
            try {
                SignedJWT signedJWT = SignedJWT.parse(jwtToken);
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                orgNameClaim = claims.getStringClaim("org_name");

                System.out.println("org claim value ===== " + orgNameClaim);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }

            if (orgNameClaim != null && orgNameClaim.equals("WA")) {
                String tokenEndpoint = "https://localhost:9443/oauth2/token";
                String subOrgToken = switchToSubOrg(tokenEndpoint, jwtToken, organization.getId());

                request.getSession(false).setAttribute("subOrgToken", jsonToAccessToken(subOrgToken));
                System.out.println("sub org token ::::: " + subOrgToken);
            } else {
                request.getSession(false).setAttribute("subOrgToken", jsonToAccessToken(jwtToken));
            }

            //request.getSession(false).setAttribute("data", organizationsResponse);
            //response.getWriter().write(apiResponse);

            response.sendRedirect(homePage);
            return;
        }

        if (!isActiveSessionPresent(request)) {
            try {
                oidcManager.sendForLogin(request, response);
            } catch (SSOAgentException e) {
                handleException(request, response, e);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private String resolveTargetPage(HttpServletRequest request, RequestContext requestContext) {

        if (StringUtils.isNotBlank(oidcAgentConfig.getHomePage())) {
            return oidcAgentConfig.getHomePage();
        }
        if (requestContext != null && StringUtils.isNotBlank((CharSequence) requestContext.getParameter(
                SSOAgentConstants.REDIRECT_URI_KEY))) {
            return requestContext.getParameter(SSOAgentConstants.REDIRECT_URI_KEY).toString();
        }
        if (StringUtils.isNotBlank(oidcAgentConfig.getIndexPage())) {
            return oidcAgentConfig.getIndexPage();
        }

        // If all the checks fail, set root path as the target page.
        String requestUrl = request.getRequestURL().toString();
        return requestUrl.substring(0, requestUrl.length() - request.getServletPath().length());
    }

    private RequestContext getRequestContext(HttpServletRequest request) {

        HttpSession session = request.getSession(false);

        if (session != null && session.getAttribute(SSOAgentConstants.REQUEST_CONTEXT) != null) {
            return (RequestContext) request.getSession(false).getAttribute(SSOAgentConstants.REQUEST_CONTEXT);
        }
        return null;
    }

    @Override
    public void destroy() {

    }

    boolean isActiveSessionPresent(HttpServletRequest request) {

        HttpSession currentSession = request.getSession(false);

        return currentSession != null
                && currentSession.getAttribute(SSOAgentConstants.SESSION_CONTEXT) != null
                && currentSession.getAttribute(SSOAgentConstants.SESSION_CONTEXT) instanceof SessionContext;
    }

    void clearSession(HttpServletRequest request) {

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    protected void handleException(HttpServletRequest request, HttpServletResponse response, SSOAgentException e)
            throws ServletException, IOException {

        String errorPage = oidcAgentConfig.getErrorPage();
        if (StringUtils.isBlank(errorPage)) {
            errorPage = buildErrorPageURL(oidcAgentConfig, request);
        }
        if (errorPage.trim().charAt(0) != '/') {
            errorPage = "/" + errorPage;
        }
        clearSession(request);
        logger.log(Level.FATAL, e.getMessage());
        request.setAttribute(SSOAgentConstants.AGENT_EXCEPTION, e);
        RequestDispatcher requestDispatcher = request.getServletContext().getRequestDispatcher(errorPage);
        requestDispatcher.forward(request, response);
    }

    private String buildErrorPageURL(OIDCAgentConfig oidcAgentConfig, HttpServletRequest request) {

        if (StringUtils.isNotBlank(oidcAgentConfig.getErrorPage())) {
            return oidcAgentConfig.getErrorPage();
        } else if (StringUtils.isNotBlank(oidcAgentConfig.getIndexPage())) {
            return oidcAgentConfig.getIndexPage();
        }
        return SSOAgentConstants.DEFAULT_CONTEXT_ROOT;
    }

    private String getAccessToken(HttpServletRequest request) {

        HttpSession currentSession = request.getSession(false);
        String accessToken = null;

        if (isActiveSessionPresent(request)) {
            final SessionContext sessionContext = (SessionContext) currentSession.getAttribute(SSOAgentConstants.SESSION_CONTEXT);
            accessToken = jsonToAccessToken(sessionContext.getAccessToken());
        }


        return accessToken;
    }

    private String jsonToAccessToken(String jsonString) {

        Gson gson = new Gson();
        TokenPayload tokenPayload = gson.fromJson(jsonString, TokenPayload.class);
        return tokenPayload.getAccess_token();
    }

    private String switchToSubOrg(String endpointUrl, String accessToken, String orgId) {
        StringBuilder response = new StringBuilder();

        URL url = null;
        try {
            url = new URL(endpointUrl);

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");

            connection.setRequestProperty("Authorization", "Basic cHg1MmEzY1RibEtqUVhWSmVqWmxMTVZNRHI0YTpaMndmWXkwY1IzYjVpdkprRWZmMzlvdEh1U0FUbjNnWlRXemdHUVRmcDFBYQ==" ); //todo:add encoded values here.
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);

            String formParams = "grant_type=" + URLEncoder.encode("organization_switch", StandardCharsets.UTF_8)
                    + "&token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8)
                    + "&scope=" + URLEncoder.encode("openid", StandardCharsets.UTF_8)
                    + "&switching_organization=" + URLEncoder.encode(orgId, StandardCharsets.UTF_8); //todo:remove hard code value


            /*connection.setRequestProperty("grant_type", "organization_switch");
            connection.setRequestProperty("token", getAccessToken(request));
            connection.setRequestProperty("scope", "openid address email groups roles internal_login");
            connection.setRequestProperty("switching_organization", orgId);*/

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = formParams.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {//todo:if respone is not 200 handle null pointer
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                in.close();
            } else {
                System.err.println("Failed to retrieve data from API. Response Code: " + responseCode);
                return null;
            }

            connection.disconnect();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return response.toString();
    }

    //todo:move http call to a util class
    private String fetchSubOrganizations(String endpointUrl, HttpServletRequest request) {
        StringBuilder response = new StringBuilder();

        URL url = null;
        try {
            url = new URL(endpointUrl);

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + getAccessToken(request)); //todo:remove hardcoded values.

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                in.close();
            } else {
                System.err.println("Failed to retrieve data from API. Response Code: " + responseCode);
                return null;
            }

            connection.disconnect();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return response.toString();
    }
}
