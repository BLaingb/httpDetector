/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mx.itesm.api.flow;

import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.onosproject.core.ApplicationId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import mx.itesm.api.ApiResponse;

/**
 * FlowApi, communicates with the flow rest api. 
 * Requires an onos application id.
 */
public class FlowApi {

    /**
     * Properties
     */
    private static Logger log = LoggerFactory.getLogger(FlowApi.class);
    private static final String BASE_PATH_FORMAT = "http://localhost:8181/onos/v1/flows?appId=%d";
    public ApplicationId appId;

    // Configures the api base path, it should include the appId as a query parameter
    private String basePath(){
        return String.format(BASE_PATH_FORMAT, appId.id());
    }

    /**
     * Methods
     */
    public FlowApi(ApplicationId appId){
        this.appId = appId;
    }

    // Post a flow rule to the flow api
    public ApiResponse postFlowRule(ObjectNode flow) {
        Client client = ClientBuilder.newClient();
        client.property(ClientProperties.FOLLOW_REDIRECTS, true);
    
        // Authenticate user with env variables or with default user (onos) and password (rocks)
        final Map<String, String> env = System.getenv();
        String user = env.getOrDefault("ONOS_WEB_USER", "onos");
        String pass = env.getOrDefault("ONOS_WEB_PASS", "rocks");
        HttpAuthenticationFeature auth = HttpAuthenticationFeature.basic(user, pass);
        client.register(auth);
    
        // Configure target
        WebTarget target = client.target(basePath());
    
        // Post flow to the api
        Response response = target.request(MediaType.APPLICATION_JSON)
                        .post(Entity.entity(flow.toString(), MediaType.APPLICATION_JSON));
    
        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
            log.error("POST failed {}\n{}", response.toString(), flow.toString());
            return new ApiResponse(false, response);
        }
        return new ApiResponse(true, response);
    }
}