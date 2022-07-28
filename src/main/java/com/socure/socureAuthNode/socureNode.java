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
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.http.protocol.Responses.noopExceptionFunction;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.getObject;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import javax.inject.Inject;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.getAttributeFromContext;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.json.JsonValue;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.DEFAULT_IDM_IDENTITY_ATTRIBUTE;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.DEFAULT_IDM_MAIL_ATTRIBUTE;
import org.forgerock.util.promise.Promise;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
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
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.stringAttribute;

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
    private final IdmIntegrationService idmIntegrationService;
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
        default String apiUrl() {
            return "";
        }

        /**
         * The header name for zero-page login that will contain the identity's password.
         */
        @Attribute(order = 200)
        default String apiKey() {
            return "";
        }
        @Attribute(order = 300)
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
    public socureNode(@Assisted Config config, @Assisted Realm realm, HttpClientHandler client, IdmIntegrationService idmIntegrationService) {
        this.config = config;
        this.realm = realm;
        this.clientHandler = client;
        this.idmIntegrationService = idmIntegrationService;

    }
    
	@Override
    public Action process(TreeContext context) throws NodeProcessException {
    	
		 // Get username of current user
    	 Optional<String> userName = stringAttribute(
                 idmIntegrationService.getAttributeFromContext(context, DEFAULT_IDM_IDENTITY_ATTRIBUTE));
         if (userName.isEmpty()) {
             userName = Optional.ofNullable(getUsernameFromObject(context));
         }
         
         //Get identity information of current user using username
         
         JsonValue existingObject = getObject(idmIntegrationService, realm, context.request.locales,
                 context.identityResource, DEFAULT_IDM_IDENTITY_ATTRIBUTE, userName)
                 .orElseThrow(() -> new NodeProcessException("Failed to retrieve existing object"));
       
         logger.error(String.valueOf(existingObject));
       //Continue adding values to match the socure docs for each module
        String firstName = existingObject.get("givenName").asString();
        String surName = existingObject.get("sn").asString();
        String physicalAddress = existingObject.get("postalAddress").asString();
        String city = existingObject.get("city").asString();
        String state = existingObject.get("stateProvince").asString();
        String zip = existingObject.get("postalCode").asString();
        String country = existingObject.get("country").asString();
        String mail = existingObject.get("mail").asString();
        String telephoneNumber = existingObject.get("telephoneNumber").asString();
        String dob = existingObject.get("dob").asString();
        String nationalId = existingObject.get("nationalId").asString();
        // Create JSON body
        JSONObject object = new JSONObject();
	      String json = null;
	      try {
	    	  JSONArray array = new JSONArray();
	    	  array.put(config.module().isActive());
	    	  
	    	  //Continue adding values to match the socure docs for each module
	    	  
	    	  object.put("modules", array);
			  object.put("firstName", firstName);
		      object.put("surName", surName);
		      object.put("physicalAddress", physicalAddress);
			  object.put("city", city);
		      object.put("state", state);
		      object.put("zip", zip);
			  object.put("country", country);
			  object.put("email", mail);
			  object.put("mobileNumber", telephoneNumber);
			  object.put("dob", dob);
			  object.put("nationalId", nationalId);
			  
		      
		      json = object.toString();


		} catch (JSONException e1) {
			e1.printStackTrace();
		}
	      //Make API call to Socure
	      HttpClient client = HttpClient.newHttpClient();
	      HttpRequest request = HttpRequest.newBuilder()
	                .uri(URI.create(config.apiUrl()))
	                .POST(BodyPublishers.ofString(json))
	                .header("Authorization", "SocureApiKey " + config.apiKey())
	                .header("Content-Type", "application/json")
	                .build();
	      
	      HttpResponse<String> response = null;
		try {
			response = client.send(request,
			            HttpResponse.BodyHandlers.ofString());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		Action.ActionBuilder action = goTo(true);
		logger.error(String.valueOf(response.statusCode()));
		logger.error(response.body());
		
		
		//address risk score validation
		try {
			 JSONObject jsonObj  = new JSONObject(response.body());
			 JSONObject jsonarr = jsonObj.getJSONObject("addressRisk");
			 double score = jsonarr.getDouble("score");
			 if(score < .9) {
				 action = goTo(false);
			 }
			
		} catch (JSONException e) {}
		
		//phone risk score validation
		try {
			 JSONObject jsonObj  = new JSONObject(response.body());
			 JSONObject jsonarr = jsonObj.getJSONObject("phoneRisk");
			 double score = jsonarr.getDouble("score");
			 if(score < .9) {
				 action = goTo(false);
			 }
			
		} catch (JSONException e) {}
		
		//email risk score validation
		try {
			 JSONObject jsonObj  = new JSONObject(response.body());
			 JSONObject jsonarr = jsonObj.getJSONObject("emailRisk");
			 double score = jsonarr.getDouble("score");
			 if(score < .9) {
				 action = goTo(false);
			 }
			
		} catch (JSONException e) {}
		
		//kyc field validation
		try {
			 JSONObject jsonObj  = new JSONObject(response.body());
			 JSONObject jsonarr = jsonObj.getJSONObject("kyc");
			 String fieldValidations = jsonarr.getString("fieldValidations");
			 JSONObject myjson = new JSONObject(fieldValidations);

            JSONArray nameArray = myjson.names();
            JSONArray valArray = myjson.toJSONArray(nameArray);
            for(int i=0;i<valArray.length();i++)
            {
            	if(valArray.getInt(i) < .2) {
            		action = goTo(false);
            	}
            	
            }
			
		} catch (JSONException e) {}
		//Determine if response should fail or success user
		if(response.statusCode() != 200) {
			action = goTo(false);
		}
		return action
                .replaceSharedState(context.sharedState.copy())
                .replaceTransientState(context.transientState.copy()).build();

    }

    private String getUsernameFromObject(TreeContext context) throws NodeProcessException {
        Optional<String> objectValue = stringAttribute(
                getAttributeFromContext(idmIntegrationService, context, DEFAULT_IDM_MAIL_ATTRIBUTE));
        logger.debug("Retrieving {} of {} {}", DEFAULT_IDM_IDENTITY_ATTRIBUTE, context.identityResource, objectValue);
        JsonValue existingObject = getObject(idmIntegrationService, realm, context.request.locales,
                context.identityResource, DEFAULT_IDM_MAIL_ATTRIBUTE, objectValue, DEFAULT_IDM_IDENTITY_ATTRIBUTE)
                .orElseThrow(() -> new NodeProcessException("Failed to retrieve existing object"));

        logger.error(existingObject.asString());
        return existingObject.get(DEFAULT_IDM_IDENTITY_ATTRIBUTE).asString();
    }

    public enum Module {
        /**
         * The lock status.
         **/
        KYC("kyc"),
        /**
         * The unlock status.
         **/
        EmailRiskScore("emailrisk"),

        AddressRiskScore("addressrisk"),

        PhoneRiskScore("phonerisk"),

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

