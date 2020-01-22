# HTTP DDoS classifiers

Contains a generic Classifier class that each classifier should inherit from. The classifier interface expose two methods:
- [void Load(String filepath)](./Classifier.java#L56): Loads the model to be used for the classification
- [int Classify(FlowData f)](./Classifier.java#L65): Classifies the flow, returning the enumerator that determines the predicted class