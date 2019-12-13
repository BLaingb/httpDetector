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

import mx.itesm.httpddosdetector.FlowData;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomTree {
    public RandomStump splitModel;
    public RandomTree subModel0;
    public RandomTree subModel1;

    /**
     * Loads the tree model to be used for the classification
     *
     * @param model JsonNode the model to be used for classification
     */
    public void Load(JsonNode model){
        splitModel = new RandomStump();
        splitModel.Load(model);
        if(model.has("0")){
            subModel0 = new RandomTree();
            subModel0.Load(model.get("0"));
        } else {
            subModel0 = null;
        }
            
        if(model.has("1")){
            subModel1 = new RandomTree();
            subModel1.Load(model.get("1"));
        } else {
            subModel1 = null;
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(ArrayList<Long> X) {
        int y = 0;
        // Get values from model
        Integer splitVariable = splitModel.splitVariable;
        Float splitValue = splitModel.splitValue;
        Integer splitSat = splitModel.splitSat;

        if(splitVariable == null){
            // If no further splitting, return the majority label
            y = splitSat;
        }else if(subModel1 == null){
            y = splitModel.Classify(X);
        }else{
            // Recurse on both sub-models
            if (X.get(splitVariable) > splitValue){
                y = subModel1.Classify(X);
            }else{
                y = subModel0.Classify(X);
            }
        }
        return y;
    }
}