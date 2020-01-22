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
package mx.itesm.httpddosdetector;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import mx.itesm.httpddosdetector.classifier.Classifier;
import mx.itesm.httpddosdetector.classifier.randomforest.RandomForestBinClassifier;

import mx.itesm.api.flow.FlowApi;
import mx.itesm.api.ApiResponse;

import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;

/**
 * Onos application to detect and mitigate HTTP DDoS Attacks
 */
@Component(immediate = true)
public class HttpDdosDetector {

    /** Properties. */
    private static Logger log = LoggerFactory.getLogger(HttpDdosDetector.class);
    private static final int PRIORITY = 128;
    private static final int ATTACK_TIMEOUT = 90; // seconds
    private static final int ATTACK_THRESHOLD = 1; // attacks per ATTACK_TIMEOUT to be considered an attack
    private static final int FLOW_RULE_TIME = 5 * 60; // 5 minutes

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new TCPPacketProcessor();

    // Selector for TCP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    // Holds the current active flows
    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();
    // Holds the current blocked flows
    private HashMap<AttackKey, FlowRuleId> blockedAttacks = new HashMap<AttackKey, FlowRuleId>();
    // Holds the current detected attack flows that aren't blocked
    private HashMap<DistributedAttackKey, LinkedList<FlowData>> attackFlows = new HashMap<DistributedAttackKey, LinkedList<FlowData>>();

    private Classifier classifier;
    private FlowApi flowApi;

    // Runs when the application is started, after activation or reinstall
    @Activate
    protected void activate() {
        // Register application to get an app id
        appId = coreService.registerApplication("mx.itesm.httpddosdetector", () -> log.info("Periscope down."));

        // Adds packet processor with CONTROL priority which is a high priority 
        // that allows to control traffic. 
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                                     Optional.empty());
        // TODO(abrahamtorres): Check if the performance of the controller is affected by using 
        // CONTROL priority, if it affects then change it to REACTIVE priority

        // Initialize the classifier and load the model to be used
        classifier = new RandomForestBinClassifier();
        classifier.Load("/models/random_forest_bin.json");

        // Initialize the flow api to communicate with the rest api
        flowApi = new FlowApi(appId);

        log.info("HTTP DDoS detector started");
    }

    // Runs on when application is stopped, when unistalled or deactivated
    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flows.clear();
        blockedAttacks.clear();
        attackFlows.clear();
        log.info("HTTP DDoS detector stopped");
    }

    // Processes the provided TCP packet
    private void processPacket(PacketContext context, Ethernet eth) {
        // Get identifiers of the packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcip = ipv4.getSourceAddress();
        int dstip = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcport = tcp.getSourcePort();
        int dstport = tcp.getDestinationPort();

        // Calculate forward and backward keys
        FlowKey forwardKey = new FlowKey(srcip, srcport, dstip, dstport, proto);
        FlowKey backwardKey = new FlowKey(dstip, dstport, srcip, srcport, proto);
        FlowData f;
        
        // Check if flow is stored
        if(flows.containsKey(forwardKey) || flows.containsKey(backwardKey)){
            // Get corresponding flow and update it
            if(flows.containsKey(forwardKey)){
                f = flows.get(forwardKey);
            }else{
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcip);
            // Calling export will generate a log of the updated flow features
            f.Export();

            // log.info("Updating flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
        } else {
            // Add new flow
            f = new FlowData(srcip, srcport, dstip, dstport, proto, eth);
            // Include forward and backward keys
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
            // log.info("Added new flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", srcip, srcport, dstip, dstport, proto);
        }

        // If connection is closed
        if(f.IsClosed()){
            // Pass through classifier
            RandomForestBinClassifier.Class flowClass = RandomForestBinClassifier.Class.valueOf(classifier.Classify(f));
            // React depending on the result
            switch(flowClass){
                case NORMAL:
                    log.info("Detected normal flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
                case ATTACK:
                    log.warn("Detected attack flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    // Add attack to the proper queue
                    LinkedList<FlowData> attackFlowsQueue;
                    DistributedAttackKey k = f.forwardKey.toDistributedAttackKey();
                    if(attackFlows.containsKey(k)){
                        attackFlowsQueue = attackFlows.get(k);
                    }else{
                        attackFlowsQueue = new LinkedList<FlowData>();
                        attackFlows.put(k, attackFlowsQueue);
                    }
                    attackFlowsQueue.add(f);
                    break;
                case ERROR:
                    log.error("Error predicting flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
            }
            // Delete from flows, since it is closed we don't expect any other packet from this flow
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            f = null;
        }

        long currTimeInSecs = System.currentTimeMillis() / 1000;
        attackFlows.forEach((distAttackKey, attackQueue)->{
            // Remove expired attack flows
            while(attackQueue.peek().flast + ATTACK_TIMEOUT < currTimeInSecs){
                attackQueue.remove();
            }; 

            // Check if host is under attack
            if(attackQueue.size() > ATTACK_THRESHOLD){
                // Check if attacker is not already blocked
                for (FlowData attack : attackQueue) {
                    AttackKey attackKey = attack.forwardKey.toAttackKey();
                    // If attacker isn't already blocked
                    if(!blockedAttacks.containsKey(attackKey)){
                        // Add flow rule to block attack
                        ApiResponse res = addFlowRule(deviceId, attackKey);
                        if(!res.result){
                            log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                            continue;
                        }
                        // Read response from the api
                        String body = res.response.readEntity(String.class);
                        JsonNode apiRes = null;
                        try {
                            ObjectMapper mapper = new ObjectMapper();
                            apiRes = mapper.readTree(body);
                        } catch (Exception e){
                            e.printStackTrace();
                        }
                        if(apiRes == null){
                            log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                            continue;
                        }

                        // Retrieve flowId and deviceId from the response, so we can later delete the flow rule
                        JsonNode newFlowRule = apiRes.get("flows").get(0);
                        FlowRuleId rule = new FlowRuleId(newFlowRule.get("deviceId").asText(), newFlowRule.get("flowId").asText());
                        blockedAttacks.put(attackKey, rule);
                        log.info("Added flow rule to block attack, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                    }
                    // Attacker is already blocked, no need to store the attacks
                    attackQueue.remove(attack);
                }
            }

            // Remove empty attack queues
            if(attackQueue.size() == 0){
                attackFlows.remove(distAttackKey);
            }
        });

        // TODO(abrahamtorres): Remove expired flow rules
    }

    // Add flow rule to block an attacker
    private ApiResponse addFlowRule(DeviceId deviceId, AttackKey attackKey){
        // Build flow rule object
        ObjectNode flowRequest = new ObjectNode(JsonNodeFactory.instance);
        
        ObjectNode flow = new ObjectNode(JsonNodeFactory.instance);
        flow.put("priority", 40000);
        flow.put("timeout", 0);
        flow.put("isPermanent", true);
        flow.put("deviceId", deviceId.toString());
        
        ObjectNode selector = flow.putObject("selector");
        
        ArrayNode criteria = selector.putArray("criteria");
        // Match TCP packets
        criteria.addObject()
        .put("type", "IP_PROTO")
        .put("protocol", "0x05");
        // Match TCP destination port of the attacked host
        criteria.addObject()
        .put("type", "TCP_DST")
        .put("tcpPort", attackKey.dstport);
        // Match destination ip of the attacked host
        IpPrefix dstIpPrefix = IpPrefix.valueOf(attackKey.dstip, IpPrefix.MAX_INET_MASK_LENGTH);
        criteria.addObject()
        .put("type", "IPV4_DST")
        .put("ip", dstIpPrefix.toString());
        // Match source ip 
        IpPrefix srcIpPrefix = IpPrefix.valueOf(attackKey.srcip, IpPrefix.MAX_INET_MASK_LENGTH);
        criteria.addObject()
        .put("type", "IPV4_SRC")
        .put("ip", srcIpPrefix.toString());
        

        ArrayNode flows = flowRequest.putArray("flows");

        flows.add(flow);
        
        return this.flowApi.postFlow(flowRequest);
    }

    // Indicates whether the specified packet corresponds to TCP packet.
    private boolean isTcpPacket(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    // Packet processor implementation, will call processPacket() for every TCP packet received
    private class TCPPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet packet = context.inPacket().parsed();
            
            if (packet == null) {
                return;
            }

            if (isTcpPacket(packet)) {
                processPacket(context, packet);
            }
        }
    }

}
