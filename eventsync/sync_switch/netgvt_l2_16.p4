/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */



#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers_l2.p4"
#include "util.p4"


#define number_of_processes 5

#define STRONG 1
//define WEAK 1

struct metadata_t {
    bit<32> iterator_0;
    bit<32> iterator_1;
    bit<32> gvt;          
    bit<32> fail;
    bit<32> round_meta;
    bit<32> current_replay;
    bit<32> current_replay_number;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    Checksum() ipv4_checksum;
    
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        ig_md.iterator_0 = 0;
        ig_md.iterator_1 = 0;
        ig_md.gvt = 0;        
        transition parse_ethernet;
    }
 
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_GVT : parse_gvt;
            default : reject;
        }
    }
    state parse_gvt {
    	pkt.extract(hdr.gvt);
    	transition accept;
    	
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);    
        ipv4_checksum.add(hdr.ipv4);
        transition accept;
    }
}


Register<bit<32>, _>(1) LVT_pid_0;
Register<bit<32>, _>(1) LVT_pid_1;
Register<bit<32>, _>(1) LVT_pid_2;
Register<bit<32>, _>(1) LVT_pid_3;
Register<bit<32>, _>(1) LVT_pid_4;
Register<bit<32>, _>(1) LVT_pid_5;
Register<bit<32>, _>(1) LVT_pid_6;
Register<bit<32>, _>(1) GVT;

Register<bit<32>, _>(2000) virtual_times;


Register<bit<32>, _>(1) last_replay;
Register<bit<32>, _>(1) sim_failure;
Register<bit<32>, _>(1) round;
Register<bit<32>, _>(1) replayed_packets;

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;
    apply {

       if(hdr.ipv4.isValid()){
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});}
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    RegisterAction<bit<32>, _, bit<32>>(sim_failure) read_sim_failure = {
    void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(last_replay) read_last_replay = {
    void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(replayed_packets) read_current_replay = {
    void apply(inout bit<32> value, out bit<32> rv){
            value = value + 1;
            rv = value;
        } 
    };

    RegisterAction<bit<32>, _, bit<32>>(round) check_round = {
    void apply(inout bit<32> value, out bit<32> rv){
            if(hdr.gvt.round == value + 1){
                value = hdr.gvt.round;
            }
            rv = value;
    }
    };

    RegisterAction<bit<32>, _, bit<32>>(round) update_round = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = value + 1;
            rv = value;
        }
    };

    bit<32> aux_min;
 
    action bounce_pkt(){
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
 
        bit<48> tmp = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;

    }

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_0) Update_lvt_pid_0 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 0 ) value = hdr.gvt.value;
            rv = value;
        }
    };
    
    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_1) Update_lvt_pid_1 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 1 ) value = hdr.gvt.value;
            rv = value;
        }
    };    

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_2) Update_lvt_pid_2 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 2 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_3) Update_lvt_pid_3 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 3 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_4) Update_lvt_pid_4 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 4 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_5) Update_lvt_pid_5 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid == 5 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(LVT_pid_6) Update_lvt_pid_6 = {
    void apply(inout bit<32> value, out bit<32> rv) {
            if ( hdr.gvt.pid ==6 ) value = hdr.gvt.value;
            rv = value;
        }
    };

    
    RegisterAction<bit<32>, _, bit<32>>(GVT) Update_GVT = {
    void apply(inout bit<32> value, out bit<32> rv) {
            value = aux_min;
//            value = min(value, 5 );
            rv = value;
        }
    };
    
    
    action drop_() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }
    action ipv4_forward(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action gvt_forward(PortId_t port, mac_addr_t dst_mac, mac_addr_t src_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ethernet.src_addr = src_mac;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = { 
            ipv4_forward;
            drop_;
        }
        size = 1024;
        default_action = drop_();
    }

    table eth_forward {
        key = {
            hdr.ethernet.src_addr: exact;
        }
        actions = {
            gvt_forward; 
        }
        size = 1024;
    }

    apply {

	if(hdr.gvt.isValid()){
	        //starts virtual time synchronization
                if(hdr.gvt.type == TYPE_DELIVER){
                    ig_intr_tm_md.mcast_grp_a =  1;
                }else{
                if( hdr.gvt.type == TYPE_FAILURE){                      /*if is a probe message just answer it */
                    hdr.gvt.type = TYPE_DELFAILURE;
                    bounce_pkt();
                }else{ 
                    if(hdr.gvt.type == TYPE_COLLECT){
                        hdr.gvt.round = check_round.execute(0); //send the updated round number to process
                        hdr.gvt.value = Update_lvt_pid_0.execute(0); //send last LVT value to process
                        bounce_pkt();
                    }else{ if( hdr.gvt.type == TYPE_REPLAY){
                        ig_md.round_meta = check_round.execute(0);
                        ig_md.current_replay = read_last_replay.execute(0);
                        #ifdef STRONG
                        //This is for strong consistency!
                        if(ig_md.round_meta != hdr.gvt.round){
		                    hdr.gvt.type = TYPE_UNORDERED;
                        }else{
                            //this is the condition to finish the strong replay
                            if(ig_md.round_meta == ig_md.current_replay){
                               hdr.gvt.type = 10;             //type restart: that is for retarting the system                            
                            }else{
                               hdr.gvt.type = TYPE_ACK;
                            }
			            }
                        bounce_pkt();
                        #endif
                        #ifdef WEAK
                        ig_md.current_replay_number = read_current_replay.execute(0); //number of replayed packets 
                        //this is the condition to finish the weak replay
                        if(ig_md.current_replay_number == ig_md.current_replay){
                           hdr.gvt.type = 10;             //type restart: that is for retarting the system
                           bounce_pkt();
                        }
                        #endif
                    }else if(hdr.gvt.type != TYPE_UNORDERED){	        
                        hdr.gvt.round = update_round.execute(0);                 
		                ig_md.iterator_0  = Update_lvt_pid_0.execute(0);
		                ig_md.iterator_1  = Update_lvt_pid_1.execute(0);
		                aux_min = min(ig_md.iterator_0, ig_md.iterator_1);
                        ig_md.iterator_1  = Update_lvt_pid_2.execute(0);
                        aux_min = min(aux_min, ig_md.iterator_1);
                        ig_md.iterator_1  = Update_lvt_pid_3.execute(0);
                        aux_min = min(aux_min, ig_md.iterator_1);
                        ig_md.iterator_1  = Update_lvt_pid_4.execute(0);
                        aux_min = min(aux_min, ig_md.iterator_1);
                        ig_md.iterator_1  = Update_lvt_pid_5.execute(0);
                        aux_min = min(aux_min, ig_md.iterator_1);
                        ig_md.iterator_1  = Update_lvt_pid_6.execute(0);
                        aux_min = min(aux_min, ig_md.iterator_1);
                        ig_md.gvt = Update_GVT.execute(0);
		                hdr.gvt.value = ig_md.gvt;
                        //this is just for droping replayed packets in the replica in case of asynchronous replication

                        //hdr.gvt.type = TYPE_DELIVER;
                        eth_forward.apply(); //forward to the replica

                        //ends virtual time synchronization
                    }
                }
            }
        }}else{ if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            }
        }
        ig_md.fail = read_sim_failure.execute(0);
        if(ig_md.fail == 1){drop_();}
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
