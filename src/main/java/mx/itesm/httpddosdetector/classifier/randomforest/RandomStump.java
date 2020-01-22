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
package mx.itesm.httpddosdetector.classifier.randomforest;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomStump {
    public Integer splitVariable = null;
    public Float splitValue = null;
    public Integer splitSat = null;
    public Integer splitNot = null;

    /**
     * Loads the stump model to be used for the classification
     *
     * @param model JsonNode the model to be used for classification
     */
    public void Load(JsonNode model){
        if(model.has("d")){
            splitVariable = model.get("d").asInt();
        } else {
            splitVariable = null;
        }
        if(model.has("x")){
            splitValue = (float) model.get("x").asDouble();
        } else {
            splitValue = null;
        }
        if(model.has("s")){
            splitSat = model.get("s").asInt();
        } else {
            splitSat = null;
        }
        if(model.has("n")){
            splitNot = model.get("n").asInt();
        } else {
            splitNot = null;
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(ArrayList<Long> X) {
        if(splitVariable == null){
            return splitSat;
        }
        int yhat = 0;
        if(X.get(splitVariable) > splitValue){
            yhat = splitSat;
        }else{
            yhat = splitNot;
        }

        return yhat;
    }
}