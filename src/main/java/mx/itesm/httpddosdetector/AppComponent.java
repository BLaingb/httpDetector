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

import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Optional;
import java.util.Properties;
import java.util.HashMap;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    /** Properties. */
    private static Logger log = LoggerFactory.getLogger(AppComponent.class);
    private static final int PRIORITY = 128;
    private static final int DROP_PRIORITY = 129;
    private static final int TIMEOUT_SEC = 60; // seconds

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected FlowRuleService flowRuleService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new TCPPacketProcessor();
    // private final FlowRuleListener flowListener = new InternalFlowListener();

    // Selector for ICMP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("mx.itesm.httpddosdetector", () -> log.info("Periscope down."));
        // flowRuleService.addListener(flowListener);
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                                     Optional.empty());
        log.info("HTTP DDoS detector started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        // flowRuleService.removeFlowRulesById(appId);
        // flowRuleService.removeListener(flowListener);
        log.info("HTTP DDoS detector stopped");
    }

    // Processes the specified TCP packet.
    private void processPacket(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcip = ipv4.getSourceAddress();
        int dstip = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcport = tcp.getSourcePort();
        int dstport = tcp.getDestinationPort();

        FlowKey key = new FlowKey(srcip, srcport, dstip, dstport, proto);
        if(flows.containsKey(key)){
            FlowData f = flows.get(key);
            f.Add(eth, srcip);
            log.info("Updating flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", srcip, srcport, dstip, dstport, proto);
        } else {
            FlowData f = new FlowData(srcip, srcport, dstip, dstport, proto, eth);
            flows.put(key, f);
            log.info("Added new flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})", srcip, srcport, dstip, dstport, proto);
        }
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
