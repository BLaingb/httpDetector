# HTTP DDoS detector 
This repository contains an ONOS application that is focused to detect and mitigate HTTP DDoS attacks. Through the usage of a random forest classifier.

## Requirements:
- Intermediate Java knowledge
- SDN basics
- ONOS basics
- Random Forest classifier (Optional)

## Project structure
- [mx.itesm.api.flow](./src/main/java/mx/itesm/api/flow) contains the code that interacts with the REST flow api.
- [mx.itesm.httpddosdetector.classifier](./src/main/java/mx/itesm/httpddosdetector/classifier) contains a generic Classifier class that every classifier used should inherit from.
- [mx.itesm.httpddosdetector.classifier.randomforest](./src/main/java/mx/itesm/httpddosdetector/classifier/randomforest) contains the implementation of the random forest classifier that loads a JSON file containing a trained model
- [mx.itesm.httpddosdetector.flow.parser](./src/main/java/mx/itesm/httpddosdetector/flow/parser) contains the code implementation in java of [flowtbag](https://github.com/DanielArndt/flowtbag) to convert packets into flows
- [mx.itesm.httpddosdetector.keys](./src/main/java/mx/itesm/httpddosdetector/keys) contain keys used for identifying flows, attacks and distributed attacks.

## Processing packets 
In order to process and analyze the packets from the network traffic, we will use a [packet processor](http://api.onosproject.org/1.7.0/org/onosproject/net/packet/PacketProcessor.html). We will be based on an ONOS sample application from the onos [repository](https://wiki.onosproject.org/display/ONOS/Building+the+ONOS+Sample+Apps), to clone it run `git clone https://gerrit.onosproject.org/onos-app-samples`. In that repository we will use the **oneping** sample app, which process a packet and just allow one ping per minute.

### Converting packets into flows
Afte we have the packet processor ready, we need to convert the packets into flows so we can pass them through our classifier. To convert them we use the [FlowData](./flow/parser/FlowData.java) class to append each packet to its corresponding flow. 

This is done on the HttpDdosDetector class in [here](./src/main/java/mx/itesm/httpddosdetector/HttpDdosDetector.java#L135-L70)

## Detecting malicious flows
When a flow is closed, we can pass it through our classifiers, in this implementation we will use a random forest classifier. 

We have previously trained the model and you can find it in the resources folder [here](./src/main/resources/models/random_forest_bin.json). The classifier has to previously load the model with the _RandomForestClassifier.Load_ method, and after that we can use the _RandomForestClassifier.Classify_ to obtain the predicted class of the provided flow.

This is done on the HttpDdosDetector [here](./src/main/java/mx/itesm/httpddosdetector/HttpDdosDetector.java#L172-L202)

## Mitigating attacks

To mitigate we will use the [FlowApi.postFlowRule](./src/main/java/mx/itesm/api/flow/FlowApi.java#L63) method. The mitigation is done on the HttpDdosDetector class in [here](./src/main/java/mx/itesm/httpddosdetector/HttpDdosDetector.java#L204-L247)
