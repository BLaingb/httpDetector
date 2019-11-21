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

import static org.onlab.util.Tools.get;

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
    private final PacketProcessor packetProcessor = new PingPacketProcessor();
    // private final FlowRuleListener flowListener = new InternalFlowListener();

    // Selector for ICMP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.oneping",
                                                () -> log.info("Periscope down."));
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
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        // PingRecord ping = new PingRecord(src, dst);
        // boolean pinged = pings.get(deviceId).contains(ping);

        // if (pinged) {
        //     // Two pings detected; ban further pings and block packet-out
        //     log.warn(MSG_PINGED_TWICE, src, dst, deviceId);
        //     banPings(deviceId, src, dst);
        //     context.block();
        // } else {
        //     // One ping detected; track it for the next minute
        //     log.info(MSG_PINGED_ONCE, src, dst, deviceId);
        //     pings.put(deviceId, ping);
        //     timer.schedule(new PingPruner(deviceId, ping), TIMEOUT_SEC * 1000);
        // }
    }

    // Indicates whether the specified packet corresponds to TCP packet.
    private boolean isTcpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    // Intercepts packets
    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isTcpPing(eth)) {
                processPacket(context, eth);
            }
        }
    }

}
