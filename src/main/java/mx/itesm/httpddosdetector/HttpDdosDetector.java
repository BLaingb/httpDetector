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
import mx.itesm.httpddosdetector.flow.parser.FlowData;
import mx.itesm.httpddosdetector.keys.AttackKey;
import mx.itesm.httpddosdetector.keys.DistributedAttackKey;
import mx.itesm.httpddosdetector.keys.FlowKey;
import mx.itesm.api.flow.FlowApi;
import mx.itesm.api.flow.FlowRuleId;
import mx.itesm.api.ApiResponse;

import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;

/////////////////////////////////
// PROCESS-ABLE CLASSIFIER TEST
import java.lang.ProcessBuilder;
import java.lang.StringBuilder;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.lang.InterruptedException;
// PROCESS-ABLE CLASSIFIER TEST
/////////////////////////////////

/**
 * Onos application to detect and mitigate HTTP DDoS Attacks
 */
@Component(immediate = true)
public class HttpDdosDetector {

    static final int TOTAL_FPACKETS = 0;
    static final int TOTAL_FVOLUME = 1;
    static final int TOTAL_BPACKETS = 2;
    static final int TOTAL_BVOLUME = 3;
    static final int FPKTL = 4;
    static final int BPKTL = 5;
    static final int FIAT = 6;
    static final int BIAT = 7;
    static final int DURATION = 8;
    static final int ACTIVE = 9;
    static final int IDLE = 10;
    static final int SFLOW_FPACKETS = 11;
    static final int SFLOW_FBYTES = 12;
    static final int SFLOW_BPACKETS = 13;
    static final int SFLOW_BBYTES = 14;
    static final int FPSH_CNT = 15;
    static final int BPSH_CNT = 16;
    static final int FURG_CNT = 17;
    static final int BURG_CNT = 18;
    static final int TOTAL_FHLEN = 19;
    static final int TOTAL_BHLEN = 20;
    static final int NUM_FEATURES = 21;

    static final int MIN = 0;
    static final int MEAN = 1;
    static final int MAX = 2;
    static final int STD = 3;
    /** Properties. */
    private static Logger log = LoggerFactory.getLogger(HttpDdosDetector.class);
    // The priority of our packet processor.
    private static final int PROCESSOR_PRIORITY = 128;
    // Is the window of time in which an attack flow is considered as active.
    private static final int ATTACK_TIMEOUT = 90; // seconds
    // Is the threshold of the number of attack flows that a host must receive in order to take action and block the attackers.
    private static final int ATTACK_THRESHOLD = 1;
    // Is the time to live of a flow rule that blocks an attacker, because we don't want to block forever that host.
    private static final int FLOW_RULE_TIME = 5 * 60; // seconds

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

    /**
     * Runs when the application is started, after activation or reinstall
     */
    @Activate
    protected void activate() {
        // Register application to get an app id
        appId = coreService.registerApplication("mx.itesm.httpddosdetector", () -> log.info("Periscope down."));

        // Adds packet processor with CONTROL priority which is a high priority 
        // that allows to control traffic. 
        packetService.addProcessor(packetProcessor, PROCESSOR_PRIORITY);
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

    /**
     * Runs on when application is stopped, when unistalled or deactivated
     */
    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flows.clear();
        blockedAttacks.clear();
        attackFlows.clear();
        log.info("HTTP DDoS detector stopped");
    }

    /**
     * Processes the provided TCP packet
     * @param context packet context
     * @param eth ethernet packet
     */
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
            // PROCESS-ABLE
            RandomForestBinClassifier.Class flowClass = RandomForestBinClassifier.Class.valueOf(execComando(f));
            // Pass through classifier
            //RandomForestBinClassifier.Class flowClass = RandomForestBinClassifier.Class.valueOf(classifier.Classify(f));
            // React depending on the result
            switch(flowClass){
                case NORMAL:
                    log.info("Detected normal flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;

                case ATTACK:
                case SLOWBODY2:
                case SLOWREAD:
                case DDOSSIM:
                case SLOWHEADERS:
                case GOLDENEYE:
                case RUDY:
                case HULK:
                case SLOWLORIS:
                    log.warn(
                            "Detected {} attack flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})",
                            flowClass,
                            f.srcip,
                            f.srcport,
                            f.dstip,
                            f.dstport,
                            f.proto
                    );                    // Add attack to the proper queue
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

    /**
     * Add flow rule to block an attacker
     * @param deviceId Device that will receive the flow rule
     * @param attackKey Identifier of the attack
     * @return Flow api response
     */
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
        
        return this.flowApi.postFlowRule(flowRequest);
    }

    /**
     * Indicates whether the specified packet corresponds to TCP packet.
     * @param eth packet to be checked
     * @return true if the packet is TCP
     */
    private boolean isTcpPacket(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    /**
     * Packet processor implementation, will call processPacket() for every TCP packet received
     */
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

    private int execComando(FlowData f){
        ArrayList<Long> bpktl = f.f[BPKTL].ToArrayList();
        ArrayList<Long> fpktlDistribution = f.f[FPKTL].ToArrayList();
        ArrayList<Long> fiat = f.f[FIAT].ToArrayList();
        ArrayList<Long> biat = f.f[BIAT].ToArrayList();
        ArrayList<Long> active = f.f[ACTIVE].ToArrayList();
        ArrayList<Long> idle = f.f[IDLE].ToArrayList();

        /////////////////////////////////////////////////////////////
        // PROCESS-ABLE CLASSIFIER TEST
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("java","-jar","process-able-classifier.jar",
                    "randomtree",
                    "/root/onos/apache-karaf-4.2.6/randomTree.appddos.model",
                    Long.toString(f.f[TOTAL_FPACKETS].Get()),
                    Long.toString(f.f[TOTAL_FVOLUME].Get()),
                    Long.toString(f.f[TOTAL_BPACKETS].Get()),
                    Long.toString(f.f[TOTAL_BVOLUME].Get()),
                    Long.toString(fpktlDistribution.get(MIN)),
                    Long.toString(fpktlDistribution.get(MEAN)),
                    Long.toString(fpktlDistribution.get(MAX)),
                    Long.toString(fpktlDistribution.get(STD)),
                    Long.toString(bpktl.get(MIN)),
                    Long.toString(bpktl.get(MEAN)),
                    Long.toString(bpktl.get(MAX)),
                    Long.toString(bpktl.get(STD)),
                    Long.toString(fiat.get(MIN)),
                    Long.toString(fiat.get(MEAN)),
                    Long.toString(fiat.get(MAX)),
                    Long.toString(fiat.get(STD)),
                    Long.toString(biat.get(MIN)),
                    Long.toString(biat.get(MEAN)),
                    Long.toString(biat.get(MAX)),
                    Long.toString(biat.get(STD)),
                    Long.toString(f.f[DURATION].Get()),
                    Long.toString(active.get(MIN)),
                    Long.toString(active.get(MEAN)),
                    Long.toString(active.get(MAX)),
                    Long.toString(active.get(STD)),
                    Long.toString(idle.get(MIN)),
                    Long.toString(idle.get(MEAN)),
                    Long.toString(idle.get(MAX)),
                    Long.toString(idle.get(STD)),
                    Long.toString(f.f[SFLOW_FPACKETS].Get()),
                    Long.toString(f.f[SFLOW_FBYTES].Get()),
                    Long.toString(f.f[SFLOW_BPACKETS].Get()),
                    Long.toString(f.f[SFLOW_BBYTES].Get()),
                    Long.toString(f.f[FPSH_CNT].Get()),
                    Long.toString(f.f[BPSH_CNT].Get()),
                    Long.toString(f.f[FURG_CNT].Get()),
                    Long.toString(f.f[BURG_CNT].Get()),
                    Long.toString(f.f[TOTAL_FHLEN].Get()),
                    Long.toString(f.f[TOTAL_BHLEN].Get())
                    );

            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }

            int exitVal = process.waitFor();
            if (exitVal == 0) {
                log.info("Successfully called process-able classifier, response:");
                log.info(output.toString()+"\n");
                return Integer.parseInt( output.toString() );
            } else {
                log.info("Abnormal behavior calling process-able classifier, response:");
                log.info(output.toString());

            }

        } catch (IOException e) {
            log.error("IOException calling process-able classifier.");
            log.error(e.getMessage());
        } catch (InterruptedException e) {
            log.error("InterruptedException calling process-able classifier.");
            log.error(e.getMessage());
        } catch (Exception e) {
            log.error("Exception calling process-able classifier.");
            log.error(e.getMessage());
        }
        return -1;
        // PROCESS-ABLE CLASSIFIER TEST
        /////////////////////////////////////////////////////////////
    }
}
