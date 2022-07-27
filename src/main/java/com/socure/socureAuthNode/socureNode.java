/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.socure.socureAuthNode;

import static org.forgerock.http.protocol.Responses.noopExceptionFunction;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.json.JsonValue;

import org.forgerock.util.promise.Promise;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import com.google.inject.assistedinject.Assisted;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = socureNode.Config.class)
public class socureNode extends AbstractDecisionNode {


    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private static final Logger logger = LoggerFactory.getLogger(socureNode.class);
    private final Config config;
    private final Realm realm;
    private final HttpClientHandler clientHandler;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 100)
        default String usernameHeader() {
            return "X-OpenAM-Username";
        }

        /**
         * The header name for zero-page login that will contain the identity's password.
         */
        @Attribute(order = 200)
        default String passwordHeader() {
            return "X-OpenAM-Password";
        }

        /**
         * The group name (or fully-qualified unique identifier) for the group that the identity must be in.
         */
        @Attribute(order = 300)
        default String groupName() {
            return "zero-page-login";
        }

        @Attribute(order = 400)
        default Module module() {
            return Module.KYC;
        }


    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public socureNode(@Assisted Config config, @Assisted Realm realm, HttpClientHandler client) {
        this.config = config;
        this.realm = realm;
        this.clientHandler = client;

    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {


        Request request;
        try {
            request = new Request().setUri("https://sandbox.socure.com/api/3.0/EmailAuthScore");
            request.setMethod("POST");
            request.setEntity("{\"modules\": [\"kyc\"]}");
        } catch (
                URISyntaxException e) {
            throw new NodeProcessException(e);
        }
        //kyc module
        List<String> list = new ArrayList<>();
        list.add(config.module().isActive());
   //     final Form form = new Form();
        //     form.add("modules", "[ \"kyc\"]");
//        form.add("userConsent", userConsent);
//        form.add("firstName", "John");
//        form.add("surName", config.surName().toString());
//        form.add("physicalAddress", config.physicalAddress);
//        form.add("city", city);
//        form.add("state", state);
//        form.add("zip", zip);
//        form.add("country", country);
//        form.add("nationalId", nationalId);
//        form.add("dob", dob());

//          form.toRequestEntity(request);
        request.addHeaders(new GenericHeader("Authorization", "SocureApiKey "), new GenericHeader("Content-Type", "application/json"));

        Promise tmxResponse = clientHandler.handle(new RootContext(), request)
                .thenAlways(closeSilentlyAsync(request)).then(closeSilently(mapToJsonValue()), noopExceptionFunction())
                .then(storeResponse(context.sharedState));
        try {
            tmxResponse.getOrThrow();
        } catch (Exception e) {
            logger.error("Unable to get response for session: ");
            throw new NodeProcessException(e);
        }
        logger.error("Response");
        return goTo(false).build();

    }

    private Function<JsonValue, Void, NodeProcessException> storeResponse(final JsonValue sharedState) {
        return response -> {
            // store the token response in the jwt token
            //sharedState.put(SESSION_QUERY_RESPONSE, response);
            //sharedState.put(REQUEST_ID, response.get(REQUEST_ID));
            return null;
        };
    }

    public static Function<Response, JsonValue, NodeProcessException> mapToJsonValue() {
        return response -> {
            try {
                logger.error(String.valueOf(response.getStatus()));
                logger.error(String.valueOf(response.getCause()));
                logger.error("Status");

                if (!response.getStatus().isSuccessful()) {
                    throw response.getCause();
                }
                return json(response.getEntity().getJson());
            } catch (Exception e) {
                throw new NodeProcessException("Unable to process request. " + response.getEntity().toString(), e);
            }
        };
    }


    public enum Module {
        /**
         * The lock status.
         **/
        KYC("kyc"),
        /**
         * The unlock status.
         **/
        EmailRiskScore("emailriskscore"),

        AddressRiskScore("addressriskscore"),

        PhoneRiskScore("phoneriskscore"),

        SigmaIdentityFraud("sigmaidentityfraud"),

        SigmaSyntheticFraud("sigmasyntheticfraud"),

        SigmaDevice("sigmadevice"),

        GlobalWatchlist("globalwatchlist"),

        DecisionMode("decisionmodule"),

        SocialMedia("socialmedia"),

        AlertList("alertlist");



        private final String isActive;

        Module(String isActive) {
            this.isActive = isActive;
        }

        /**
         * Returns true if the status is 'isActive'.
         *
         * @return the status.
         */
        public String isActive() {
            return isActive;
        }
    }
}
//

