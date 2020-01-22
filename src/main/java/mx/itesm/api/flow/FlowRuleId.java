package mx.itesm.api.flow;

// Response from the REST flow api
public class FlowRuleId {
    public String deviceId; 
    public String flowId; 
 
    public FlowRuleId(String deviceId, String flowId) {
       this.deviceId = deviceId;
       this.flowId = flowId;
    }
 
 }