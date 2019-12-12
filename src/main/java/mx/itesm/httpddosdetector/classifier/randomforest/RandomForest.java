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
import mx.itesm.httpddosdetector.Helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomForest {
    private static Logger log = LoggerFactory.getLogger(RandomForest.class);

    public boolean isLoaded = false;
    public ArrayList<RandomTree> trees;

    /**
     * Loads the model to be used for the classification
     *
     * @param json ObjectNode the array of trees to be used in the classification
     */
    public void Load(ObjectNode json){
        if(json.isArray()){
            // Iterate over tree array and parse it
            json.arrayNode().forEach( treeData -> { 
                RandomTree t = new RandomTree();
                t.Load(treeData);
                trees.add(t);
            } );
            isLoaded = true;
        } else {
            log.error("Couldn't load json into random forest because json is not an array");
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(FlowData f) {
        ArrayList<Integer> predictions = new ArrayList<Integer>();
        for(int i = 0; i < trees.size(); i++){
            predictions.add(trees.get(i).Classify(f));
        }
        return Helpers.mode(predictions);
    }
}