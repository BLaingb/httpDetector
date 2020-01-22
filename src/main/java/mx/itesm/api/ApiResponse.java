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
package mx.itesm.api;

import javax.ws.rs.core.Response;

// Returned response from rest api
public class ApiResponse{

    // Whether the request was successful or not
    public boolean result;
    // Actual response from the api
    public Response response;

    public ApiResponse(boolean result, Response response){
        this.response = response;
        this.result = result;
    }
}