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

import mx.itesm.httpddosdetector.classifier.Classifier;
import mx.itesm.httpddosdetector.classifier.randomforest.codec.RandomForestCodec;
import mx.itesm.httpddosdetector.flow.parser.FlowData;
import mx.itesm.httpddosdetector.Helpers;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onosproject.rest.AbstractWebResource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classifier class to predict http ddos attacks with RandomForests
 */
public class RandomForestBinClassifier extends Classifier {
    public enum Class {
        /**
         * Indicates if there was an error while classifying the flow
         */
        ERROR(-1),
        /**
         * Indicates if the flow is part of normal network traffic
         */
        NORMAL(0),
        /**
         * Indicates if the flow is part of a http ddos attack
         */
        ATTACK(1);

        private final int value;

        private Class(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static Class valueOf(int value) {
            switch(value){
                case 0:
                    return Class.NORMAL;
                case 1:
                    return Class.ATTACK;
                default:
                    return Class.ERROR;
            }
        }
    }

    private static Logger log = LoggerFactory.getLogger(RandomForestBinClassifier.class);

    private RandomForest forest;

    /**
     * Loads the model to be used for the classification
     *
     * @param filepath String the model to be loaded on the classifier
     */
    @Override
    public void Load(String filepath){
        RandomForestCodec codec = new RandomForestCodec();
        ObjectNode json = Helpers.readJsonFile(filepath);
        AbstractWebResource context = new AbstractWebResource();

        if (json != null) {
            forest = codec.decode(json, context);
            if(forest.isLoaded){
                super.Load(filepath);
            }
        } else {
            log.error("Random forests json is null");
        }

        if(isLoaded){
            log.info("Random forest classifier loaded");
        } else{
            log.error("Error while loading random forest classifier");
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    @Override
    public int Classify(FlowData f){
        if(super.Classify(f) == -1){
            return Class.ERROR.value;
        }
        return forest.Classify(f);
    }
}