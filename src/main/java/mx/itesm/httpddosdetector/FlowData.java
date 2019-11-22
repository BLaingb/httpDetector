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

/**
 * FlowData, represents the relevant features of a flow
 */
public class FlowData {

    /**
     * Constants
     */
    static final int IP_TCP = 6;
    static final int IP_UDP = 17;

    static final int P_FORWARD = 0;
    static final int P_BACKWARD = 1;

    static final int ADD_SUCCESS = 0;
    static final int ADD_CLOSED = 1;
    static final int ADD_IDLE = 2;

    /**
     * Configurables
     */
    static final int FLOW_TIMEOUT = 600000000;
    static final int IDLE_THRESHOLD = 1000000;

    /**
     * Features indexes
     */
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

    /**
     * Properties
     */
    IFlowFeature[] f; // A map of the features to be exported
    boolean valid; // Has the flow met the requirements of a bi-directional flow
    long activeStart; // The starting time of the latest activity
    long firstTime; // The time of the first packet in the flow
    long flast; // The time of the last packet in the forward direction
    long blast; // The time of the last packet in the backward direction
    TcpState cstate; // Connection state of the client
    TcpState sstate; // Connection state of the server
    boolean hasData; // Whether the connection has had any data transmitted.
    boolean isBidir; // Is the flow bi-directional?
    short pdir; // Direction of the current packet
    String srcip; // IP address of the source (client)
    int srcport; // Port number of the source connection
    String dstip; // IP address of the destination (server)
    int dstport; // Port number of the destionation connection.
    byte proto; // The IP protocol being used for the connection.
    byte dscp; // The first set DSCP field for the flow.

    public FlowData(String srcip, int srcport, String dstip, int dstport, byte proto, Ethernet packet, long id) {
        this.f = new IFlowFeature[NUM_FEATURES];
        this.valid = false;
        this.f[TOTAL_FPACKETS] = new ValueFlowFeature(0);
        this.f[TOTAL_FVOLUME] = new ValueFlowFeature(0);
        this.f[TOTAL_BPACKETS] = new ValueFlowFeature(0);
        this.f[TOTAL_BVOLUME] = new ValueFlowFeature(0);
        this.f[FPKTL] = new DistributionFlowFeature(0);
        this.f[BPKTL] = new DistributionFlowFeature(0);
        this.f[FIAT] = new DistributionFlowFeature(0);
        this.f[BIAT] = new DistributionFlowFeature(0);
        this.f[DURATION] = new ValueFlowFeature(0);
        this.f[ACTIVE] = new DistributionFlowFeature(0);
        this.f[IDLE] = new DistributionFlowFeature(0);
        this.f[SFLOW_FPACKETS] = new ValueFlowFeature(0);
        this.f[SFLOW_FBYTES] = new ValueFlowFeature(0);
        this.f[SFLOW_BPACKETS] = new ValueFlowFeature(0);
        this.f[SFLOW_BBYTES] = new ValueFlowFeature(0);
        this.f[FPSH_CNT] = new ValueFlowFeature(0);
        this.f[BPSH_CNT] = new ValueFlowFeature(0);
        this.f[FURG_CNT] = new ValueFlowFeature(0);
        this.f[BURG_CNT] = new ValueFlowFeature(0);
        this.f[TOTAL_FHLEN] = new ValueFlowFeature(0);
        this.f[TOTAL_BHLEN] = new ValueFlowFeature(0);
        // Basic flow identification criteria
        this.srcip = srcip;
        this.srcport = srcport;
        this.dstip = dstip;
        this.dstport = dstport;
        this.proto = proto;
        // this.dscp = uint8(pkt["dscp"])
        // ---------------------------------------------------------
        this.f[TOTAL_FPACKETS].Set(1);
        // length := pkt["len"]
        // this.f[TOTAL_FVOLUME].Set(length)
        // this.f[FPKTL].Add(length)
        // this.firstTime = pkt["time"]
        this.flast = this.firstTime;
        this.activeStart = this.firstTime;
        if (this.proto == IPv4.PROTOCOL_TCP) {
            // TCP specific code:
            this.cstate = new TcpState(TcpState.State.START);
            this.sstate = new TcpState(TcpState.State.START);
            // if (TcpState.tcpSet(TCP_PSH, pkt["flags"])) {
            // this.f[FPSH_CNT].Set(1);
            // }
            // if (TcpState.tcpSet(TCP_URG, pkt["flags"])) {
            // this.f[FURG_CNT].Set(1);
            // }
        }
        // this.f[TOTAL_FHLEN].Set(pkt["iphlen"] + pkt["prhlen"])

        this.hasData = false;
        this.pdir = P_FORWARD;
        // this.updateStatus(pkt);
    }

    void updateTcpState(Ethernet packet) {
        // cstate.setState(pkt["flags"], P_FORWARD, pdir);
        // sstate.setState(pkt["flags"], P_BACKWARD, pdir);
    }
    
    void updateStatus(Ethernet packet) {
        if (proto == IP_UDP) {
            if (valid) {
                return;
            }
            // if (pkt["len"] > 8) {
            //     hasData = true;
            // }
            if (hasData && isBidir) {
                valid = true;
            }
        } else if (proto == IP_TCP) {
            if (!valid) {
                if (cstate.getState() == TcpState.State.ESTABLISHED) {
                    // if (pkt["len"] > (pkt["iphlen"] + pkt["prhlen"])) {
                    //     valid = true;
                    // }
                }
            }
            updateTcpState(packet);
        }
    }
    
    long getLastTime() {
        if (blast == 0) {
            return flast;
        }
        if (flast == 0) {
            return blast;
        }
        if (flast > blast) {
            return flast;
        }
        return blast;
    }
    
    int Add(Ethernet packet, String srcip) {
        // now := pkt["time"]
        long last = getLastTime();
        // long diff = now - last;
        // if (diff > FLOW_TIMEOUT) {
        //     return ADD_IDLE;
        // }
        // if (now < last) {
        //     log.Printf("Flow: ignoring reordered packet. %d < %d\n", now, last);
        //     return ADD_SUCCESS;
        // }
        // length := pkt["len"]
        // hlen := pkt["iphlen"] + pkt["prhlen"]
        // if (now < firstTime) {
        //     log.Fatalf("Current packet is before start of flow. %d < %d\n",
        //         now,
        //         firstTime)
        // }
        if (this.srcip == srcip) {
            pdir = P_FORWARD;
        } else {
            pdir = P_BACKWARD;
        }
        // if (diff > IDLE_THRESHOLD) {
        //     f[IDLE].Add(diff)
        //     // Active time stats - calculated by looking at the previous packet
        //     // time and the packet time for when the last idle time ended.
        //     diff = last - activeStart
        //     f[ACTIVE].Add(diff)
    
        //     flast = 0
        //     blast = 0
        //     activeStart = now
        // }
        if (pdir == P_FORWARD) {
            if (dscp == 0) {
                // dscp = uint8(pkt["dscp"]);
            }
            // Packet is travelling in the forward direction
            // Calculate some statistics
            // Packet length
            // f[FPKTL].Add(length)
            // f[TOTAL_FVOLUME].Add(length)
            // f[TOTAL_FPACKETS].Add(1)
            // f[TOTAL_FHLEN].Add(hlen)
            // Interarrival time
            if (flast > 0) {
                // diff = now - flast
                // f[FIAT].Add(diff)
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                // if tcpSet(TCP_PSH, pkt["flags"]) {
                //     f[FPSH_CNT].Add(1)
                // }
                // if tcpSet(TCP_URG, pkt["flags"]) {
                //     f[FURG_CNT].Add(1)
                // }
                // Update the last forward packet time stamp
            }
            // flast = now
        } else {
            // Packet is travelling in the backward direction
            isBidir = true;
            if (dscp == 0) {
                // dscp = uint8(pkt["dscp"]);
            }
            // Calculate some statistics
            // Packet length
            // f[BPKTL].Add(length)
            // f[TOTAL_BVOLUME].Add(length) // Doubles up as c_bpktl_sum from NM
            // f[TOTAL_BPACKETS].Add(1)
            // f[TOTAL_BHLEN].Add(hlen)
            // Inter-arrival time
            if (blast > 0) {
                // diff = now - blast
                // f[BIAT].Add(diff)
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                // if (tcpSet(TCP_PSH, pkt["flags"])) {
                //     f[BPSH_CNT].Add(1)
                // }
                // if (tcpSet(TCP_URG, pkt["flags"])) {
                //     f[BURG_CNT].Add(1)
                // }
            }
            // Update the last backward packet time stamp
            // blast = now;
        }
    
        // Update the status (validity, TCP connection state) of the flow.
        updateStatus(packet);
    
        if (proto == IP_TCP &&
            cstate.getState() == TcpState.State.CLOSED &&
            sstate.getState() == TcpState.State.CLOSED) {
            return ADD_CLOSED;
        }
        return ADD_SUCCESS;
    }
    
    void Export() {
        if (!valid) {
            return;
        }
    
        // -----------------------------------
        // First, lets consider the last active time in the calculations in case
        // this changes something.
        // -----------------------------------
        long diff = getLastTime() - activeStart;
        f[ACTIVE].Add(diff);
    
        // ---------------------------------
        // Update Flow stats which require counters or other final calculations
        // ---------------------------------
    
        // More sub-flow calculations
        if (f[ACTIVE].Get() > 0) {
            f[SFLOW_FPACKETS].Set(f[TOTAL_FPACKETS].Get() / f[ACTIVE].Get());
            f[SFLOW_FBYTES].Set(f[TOTAL_FVOLUME].Get() / f[ACTIVE].Get());
            f[SFLOW_BPACKETS].Set(f[TOTAL_BPACKETS].Get() / f[ACTIVE].Get());
            f[SFLOW_BBYTES].Set(f[TOTAL_BVOLUME].Get() / f[ACTIVE].Get());
        }
        f[DURATION].Set(getLastTime() - firstTime);
        if (f[DURATION].Get() < 0) {
            // log.Fatalf("duration (%d) < 0", f[DURATION]);
        }
    
        // fmt.Printf("%s,%d,%s,%d,%d",
        //     srcip,
        //     srcport,
        //     dstip,
        //     dstport,
        //     proto)
        for (int i = 0; i < NUM_FEATURES; i++) {
            // fmt.Printf(",%s", f[i].Export());
        }
        // fmt.Printf(",%d", dscp)
        // fmt.Printf(",%d", firstTime)
        // fmt.Printf(",%d", flast)
        // fmt.Printf(",%d", blast)
        // fmt.Println()
    }
    
    boolean CheckIdle(long time) {
        if ((time - getLastTime()) > FLOW_TIMEOUT) {
            return true;
        }
        return false;
    }
    
}