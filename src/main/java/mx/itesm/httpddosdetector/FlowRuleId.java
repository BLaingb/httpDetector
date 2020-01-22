package mx.itesm.httpddosdetector;

public class FlowRuleId {
    public String deviceId; 
    public String flowId; 
 
    public FlowRuleId(String deviceId, String flowId) {
       this.deviceId = deviceId;
       this.flowId = flowId;
    }
 
 }