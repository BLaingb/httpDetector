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
package mx.itesm.httpddosdetector.flow.parser;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

import mx.itesm.httpddosdetector.keys.FlowKey;

/**
 * FlowData, represents the relevant features of a flow
 */
public class FlowData {
    private static Logger log = LoggerFactory.getLogger(FlowData.class);

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
    public IFlowFeature[] f; // A map of the features to be exported
    public boolean valid; // Has the flow met the requirements of a bi-directional flow
    public long activeStart; // The starting time of the latest activity
    public long firstTime; // The time of the first packet in the flow
    public long flast; // The time of the last packet in the forward direction
    public long blast; // The time of the last packet in the backward direction
    public TcpState cstate; // Connection state of the client
    public TcpState sstate; // Connection state of the server
    public boolean hasData; // Whether the connection has had any data transmitted.
    public boolean isBidir; // Is the flow bi-directional?
    public short pdir; // Direction of the current packet
    public int srcip; // IP address of the source (client)
    public int srcport; // Port number of the source connection
    public int dstip; // IP address of the destination (server)
    public int dstport; // Port number of the destionation connection.
    public byte proto; // The IP protocol being used for the connection.
    public byte dscp; // The first set DSCP field for the flow.
    public FlowKey forwardKey;
    public FlowKey backwadKey;

    public FlowData(int srcip, int srcport, int dstip, int dstport, byte proto, Ethernet packet) {
        this.forwardKey = new FlowKey(srcip, srcport, dstip, dstport, proto);
        this.backwadKey = new FlowKey(dstip, dstport, srcip, srcport, proto);
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
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        this.srcip = srcip;
        this.srcport = srcport;
        this.dstip = dstip;
        this.dstport = dstport;
        this.proto = proto;
        this.dscp = ipv4.getDscp();
        // ---------------------------------------------------------
        this.f[TOTAL_FPACKETS].Set(1);
        long length = ipv4.getTotalLength();
        short flags = tcp.getFlags();
        this.f[TOTAL_FVOLUME].Set(length);
        this.f[FPKTL].Add(length);
        this.firstTime = System.currentTimeMillis() / 1000;
        this.flast = this.firstTime;
        this.activeStart = this.firstTime;
        if (this.proto == IPv4.PROTOCOL_TCP) {
            // TCP specific code:
            this.cstate = new TcpState(TcpState.State.START);
            this.sstate = new TcpState(TcpState.State.START);
            if (TcpState.tcpSet(TcpState.TCP_PSH, flags)) {
                this.f[FPSH_CNT].Set(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                this.f[FURG_CNT].Set(1);
            }
        }
        this.f[TOTAL_FHLEN].Set(ipv4.getHeaderLength());

        this.hasData = false;
        this.pdir = P_FORWARD;
        this.updateStatus(packet);
    }

    public boolean IsClosed(){
        return cstate.getState() == TcpState.State.CLOSED && sstate.getState() == TcpState.State.CLOSED;
    }

    public int Add(Ethernet packet, int srcip) {
        long now = System.currentTimeMillis() / 1000;
        long last = getLastTime();
        long diff = now - last;
        if (diff > FLOW_TIMEOUT) {
            return ADD_IDLE;
        }
        if (now < last) {
            log.info("Flow: ignoring reordered packet. {} < {}\n", now, last);
            return ADD_SUCCESS;
        }
        IPv4 ipv4 = (IPv4) packet.getPayload();
        long length = ipv4.getTotalLength();
        long hlen = ipv4.getHeaderLength();
        byte flags = ipv4.getFlags();
        if (now < firstTime) {
            log.error("Current packet is before start of flow. {} < {}\n", now, firstTime);
        }
        if (this.srcip == srcip) {
            pdir = P_FORWARD;
        } else {
            pdir = P_BACKWARD;
        }
        if (diff > IDLE_THRESHOLD) {
            f[IDLE].Add(diff);
            // Active time stats - calculated by looking at the previous packet
            // time and the packet time for when the last idle time ended.
            diff = last - activeStart;
            f[ACTIVE].Add(diff);
    
            flast = 0;
            blast = 0;
            activeStart = now;
        }
        if (pdir == P_FORWARD) {
            // Packet is travelling in the forward direction
            // Calculate some statistics
            // Packet length
            f[FPKTL].Add(length);
            f[TOTAL_FVOLUME].Add(length);
            f[TOTAL_FPACKETS].Add(1);
            f[TOTAL_FHLEN].Add(hlen);
            // Interarrival time
            if (flast > 0) {
                diff = now - flast;
                f[FIAT].Add(diff);
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                if (TcpState.tcpSet(TcpState.TCP_PSH, flags)) {
                    f[FPSH_CNT].Add(1);
                }
                if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                    f[FURG_CNT].Add(1);
                }
                // Update the last forward packet time stamp
            }
            flast = now;
        } else {
            // Packet is travelling in the backward direction
            isBidir = true;
            if (dscp == 0) {
                dscp = ipv4.getDscp();
            }
            // Calculate some statistics
            // Packet length
            f[BPKTL].Add(length);
            f[TOTAL_BVOLUME].Add(length); // Doubles up as c_bpktl_sum from NM
            f[TOTAL_BPACKETS].Add(1);
            f[TOTAL_BHLEN].Add(hlen);
            // Inter-arrival time
            if (blast > 0) {
                diff = now - blast;
                f[BIAT].Add(diff);
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                if (TcpState.tcpSet(TcpState.TCP_PSH, flags)) {
                    f[BPSH_CNT].Add(1);
                }
                if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                    f[BURG_CNT].Add(1);
                }
            }
            // Update the last backward packet time stamp
            blast = now;
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
    
    public void Export() {
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
            log.error("duration ({}) < 0", f[DURATION]);
        }
        String exported = String.format("%d,%d,%d,%d,%d", srcip, srcport, dstip, dstport, proto);
        for (int i = 0; i < NUM_FEATURES; i++) {
            exported += String.format(",%s", f[i].Export());
        }
        exported += String.format(",%d", dscp);
        exported += String.format(",%d", firstTime);
        exported += String.format(",%d", flast);
        exported += String.format(",%d", blast);
        log.info(exported);
    }
    
    public boolean CheckIdle(long time) {
        if ((time - getLastTime()) > FLOW_TIMEOUT) {
            return true;
        }
        return false;
    }
    
    public ArrayList<Long> ToArrayList(){
        if (!valid) {
            return null;
        }
        ArrayList<Long> array = new ArrayList<Long>();

        // Sample attack flow
        // array.add(13l);
        // array.add(5220l);
        // array.add(11l);
        // array.add(1964l);
        // array.add(52l);
        // array.add(401l);
        // array.add(726l);
        // array.add(336l);
        // array.add(52l);
        // array.add(178l);
        // array.add(264l);
        // array.add(99l);
        // array.add(5l);
        // array.add(0l);
        // array.add(5l);
        // array.add(1l);
        // array.add(5l);
        // array.add(1l);
        // array.add(5l);
        // array.add(2l);
        // array.add(10l);
        // array.add(10l);
        // array.add(10l);
        // array.add(10l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(13l);
        // array.add(5220l);
        // array.add(11l);
        // array.add(1964l);
        // array.add(7l);
        // array.add(7l);
        // array.add(0l);
        // array.add(0l);
        // array.add(684l);
        // array.add(580l);

        // return array;
    
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
            log.error("duration ({}) < 0", f[DURATION]);
        }
        for (int i = 0; i < NUM_FEATURES; i++) {
            ArrayList<Long> featureComponents = f[i].ToArrayList();
            for (int j = 0; j < featureComponents.size(); j++){
                array.add(featureComponents.get(j));
            }
        }
        return array;
    }

    private void updateTcpState(Ethernet packet) {
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        short flags = tcp.getFlags();
        cstate.setState(flags, P_FORWARD, pdir);
        sstate.setState(flags, P_BACKWARD, pdir);
    }
    
    private void updateStatus(Ethernet packet) {
        IPv4 ipv4 = (IPv4) packet.getPayload();
        long length = ipv4.getTotalLength();
        if (proto == IP_UDP) {
            if (valid) {
                return;
            }
            if (length > 8) {
                hasData = true;
            }
            if (hasData && isBidir) {
                valid = true;
            }
        } else if (proto == IP_TCP) {
            if (!valid) {
                if (cstate.getState() == TcpState.State.ESTABLISHED) {
                    if (length > ipv4.getHeaderLength()) {
                        valid = true;
                    }
                }
            }
            updateTcpState(packet);
        }
    }
    
    private long getLastTime() {
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

    @Override   
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowData))
            return false;
        FlowData ref = (FlowData) obj;
        return this.forwardKey.equals(ref.forwardKey) && this.backwadKey.equals(ref.backwadKey);
    }
    
}