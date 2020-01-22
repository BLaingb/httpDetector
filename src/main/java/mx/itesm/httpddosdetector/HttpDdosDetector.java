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
import java.util.Queue;

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
 * Skeletal ONOS application component.
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

    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();
    private HashMap<AttackKey, FlowRuleId> blockedAttacks = new HashMap<AttackKey, FlowRuleId>();
    private Queue<FlowData> attackFlows = new LinkedList<>();

    private Classifier classifier;
    private FlowApi flowApi;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("mx.itesm.httpddosdetector", () -> log.info("Periscope down."));
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                                     Optional.empty());
        log.info("HTTP DDoS detector started");
        classifier = new RandomForestBinClassifier();
        classifier.Load("/models/random_forest_bin.json");

        flowApi = new FlowApi(appId);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        log.info("HTTP DDoS detector stopped");
    }

    // Processes the specified TCP packet.
    private void processPacket(PacketContext context, Ethernet eth) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcip = ipv4.getSourceAddress();
        int dstip = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcport = tcp.getSourcePort();
        int dstport = tcp.getDestinationPort();

        FlowKey forwardKey = new FlowKey(srcip, srcport, dstip, dstport, proto);
        FlowKey backwardKey = new FlowKey(dstip, dstport, srcip, srcport, proto);
        FlowData f;
        if(flows.containsKey(forwardKey) || flows.containsKey(backwardKey)){
            // Update flow
            if(flows.containsKey(forwardKey)){
                f = flows.get(forwardKey);
            }else{
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcip);
            // log.info("Updating flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
            f.Export();
        } else {
            // Add new flow
            f = new FlowData(srcip, srcport, dstip, dstport, proto, eth);
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
            // log.info("Added new flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", srcip, srcport, dstip, dstport, proto);
        }

        if(f.IsClosed()){
            // Pass through classifier
            RandomForestBinClassifier.Class flowClass = RandomForestBinClassifier.Class.valueOf(classifier.Classify(f));
            switch(flowClass){
                case NORMAL:
                    log.info("Detected normal flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
                case ATTACK:
                    log.warn("Detected attack flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    attackFlows.add(f);
                    break;
                case ERROR:
                    log.error("Error predicting flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
            }
            // Delete from flows
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            f = null;
        }

        // Remove expired attack flows
        long currTimeInSecs = System.currentTimeMillis() / 1000;
        while(attackFlows.peek().flast + ATTACK_TIMEOUT < currTimeInSecs){
            attackFlows.remove();
        };

        // Check if any host is under attack
        if(attackFlows.size() > ATTACK_THRESHOLD){
            // Check if attacker is not already blocked
            for (FlowData attack : attackFlows) {
                AttackKey attackKey = attack.forwardKey.toAttackKey();
                if(!blockedAttacks.containsKey(attackKey)){
                    // Add flow rule to block attack
                    ApiResponse res = addFlowRule(deviceId, attackKey);
                    if(!res.result){
                        log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                        continue;
                    }
                    String body = res.response.readEntity(String.class);
                    JsonNode apiRes = null;
                    try {
                        //Read JSON body
                        ObjectMapper mapper = new ObjectMapper();
                        apiRes = mapper.readTree(body);
                    } catch (Exception e){
                        e.printStackTrace();
                    }
                    if(apiRes == null){
                        log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                        continue;
                    }

                    JsonNode newFlowRule = apiRes.get("flows").get(0);
                    FlowRuleId rule = new FlowRuleId(newFlowRule.get("deviceId").asText(), newFlowRule.get("flowId").asText());
                    blockedAttacks.put(attackKey, rule);
                    log.info("Added flow rule to block attack, Key(srcip: {}, dstip: {}, dstport: {})", attack.srcip, attack.dstip, attack.dstport);
                }
            }
        }

        // Remove expired flow rules
    }

    private ApiResponse addFlowRule(DeviceId deviceId, AttackKey attackKey){
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

    // Intercepts packets
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
