/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 100
#define SKETCH_CELL_BIT_WIDTH 64
#define ROUND_SIZE 3
#define RECIRCULATE_THRESH 3
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4

#define REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) reg##num
#define FIVE_TUPLE {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}
#define SKETCH_COUNT(num, algorithm) \
hash(meta.index_reg##num, HashAlgorithm.algorithm, (bit<16>)0, FIVE_TUPLE, (bit<32>)SKETCH_BUCKET_LENGTH);\
reg##num.read(meta.value_reg##num, meta.index_reg##num); \
meta.value_reg##num = meta.value_reg##num + 1; \
reg##num.write(meta.index_reg##num, meta.value_reg##num)
#define REG_RESET(num) \
reg##num.read(meta.value_reg##num, meta.index_reg##num); \
meta.value_reg##num = meta.value_reg##num - RECIRCULATE_THRESH; \
reg##num.write(meta.index_reg##num, meta.value_reg##num)

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    REGISTER(0);
    REGISTER(1);
    REGISTER(2);

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action sketch_count(){
        SKETCH_COUNT(0, crc32);
        SKETCH_COUNT(1, crc16);
        SKETCH_COUNT(2, identity);
    }

    action dequeue_count(){
        reg0.read(meta.value_reg0, meta.index_reg0);
        reg1.read(meta.value_reg1, meta.index_reg1);
        reg2.read(meta.value_reg2, meta.index_reg2);
        if (meta.value_reg0 >= RECIRCULATE_THRESH){
            meta.value_reg0 = meta.value_reg0 - RECIRCULATE_THRESH;
        }
        if (meta.value_reg1 >= RECIRCULATE_THRESH){
            meta.value_reg1 = meta.value_reg1 - RECIRCULATE_THRESH;
        }
        if (meta.value_reg2 >= RECIRCULATE_THRESH){
            meta.value_reg2 = meta.value_reg2 - RECIRCULATE_THRESH;
        }
        reg0.write(meta.index_reg0, meta.value_reg0);
        reg1.write(meta.index_reg1, meta.value_reg1);
        reg2.write(meta.index_reg2, meta.value_reg2);
    }

    action retrieve_min(){
        if (meta.value_reg0 <= meta.value_reg1){
            if (meta.value_reg0 <= meta.value_reg2){
                meta.value_min = meta.value_reg0;
            }
        }

        if (meta.value_reg1 <= meta.value_reg0){
            if (meta.value_reg1 <= meta.value_reg2){
                meta.value_min = meta.value_reg1;
            }
        }

        if (meta.value_reg2 <= meta.value_reg0){
            if (meta.value_reg2 <= meta.value_reg1){
                meta.value_min = meta.value_reg2;
            }
        }
    }

    action calculate_priority(){
        if (meta.value_min < ROUND_SIZE){
            meta.value_priority = 0;
        } 

        if (meta.value_min >= ROUND_SIZE && meta.value_min < 2*ROUND_SIZE){
            meta.value_priority = 1;
        } 

        if (meta.value_min >= 2*ROUND_SIZE && meta.value_min < 3*ROUND_SIZE){
            meta.value_priority = 2;
        } 

        if (meta.value_min >= 3*ROUND_SIZE && meta.value_min < 4*ROUND_SIZE){
            meta.value_priority = 3;
        } 
        
        if (meta.value_min >= 4*ROUND_SIZE && meta.value_min < 5*ROUND_SIZE){
            meta.value_priority = 4;
        } 

        if (meta.value_min >= 5*ROUND_SIZE && meta.value_min < 6*ROUND_SIZE){
            meta.value_priority = 5;
        } 

        if (meta.value_min >= 6*ROUND_SIZE && meta.value_min < 7*ROUND_SIZE){
            meta.value_priority = 6;
        } 

        if (meta.value_min >= 7*ROUND_SIZE && meta.value_min < 8*ROUND_SIZE){
            meta.value_priority = 7;
        } 
    }

    action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

    apply {
        if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_RECIRC){
            sketch_count();
            retrieve_min();
            calculate_priority();
            //standard_metadata.priority = meta.value_priority;
            standard_metadata.priority = (bit<3>) 0;
        } else {
            dequeue_count();
            mark_to_drop(standard_metadata);
        }
        forwarding.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    REGISTER(0);
    REGISTER(1);
    REGISTER(2);

    action sketch_count(){
        SKETCH_COUNT(0, crc32);
        SKETCH_COUNT(1, crc16);
        SKETCH_COUNT(2, identity);
    }
    action reg_reset(){
        reg0.read(meta.value_reg0, meta.index_reg0);
        reg1.read(meta.value_reg1, meta.index_reg1);
        reg2.read(meta.value_reg2, meta.index_reg2);
        if (meta.value_reg0 >= RECIRCULATE_THRESH){
            meta.value_reg0 = meta.value_reg0 - RECIRCULATE_THRESH;
        }
        if (meta.value_reg1 >= RECIRCULATE_THRESH){
            meta.value_reg1 = meta.value_reg1 - RECIRCULATE_THRESH;
        }
        if (meta.value_reg2 >= RECIRCULATE_THRESH){
            meta.value_reg2 = meta.value_reg2 - RECIRCULATE_THRESH;
        }
        reg0.write(meta.index_reg0, meta.value_reg0);
        reg1.write(meta.index_reg1, meta.value_reg1);
        reg2.write(meta.index_reg2, meta.value_reg2);
    }

    action retrieve_min(){
        if (meta.value_reg0 <= meta.value_reg1){
            if (meta.value_reg0 <= meta.value_reg2){
                meta.value_min = meta.value_reg0;
            }
        }

        if (meta.value_reg1 <= meta.value_reg0){
            if (meta.value_reg1 <= meta.value_reg2){
                meta.value_min = meta.value_reg1;
            }
        }

        if (meta.value_reg2 <= meta.value_reg0){
            if (meta.value_reg2 <= meta.value_reg1){
                meta.value_min = meta.value_reg2;
            }
        }
    }

    apply {  
           
        if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_RECIRC && standard_metadata.instance_type != PKT_INSTANCE_TYPE_EGRESS_CLONE){
            sketch_count();
            retrieve_min(); 
        }     

        if (meta.value_min >= RECIRCULATE_THRESH){
            //clone_preserving_field_list(CloneType.E2E, 5, 0);  
            //recirculate_preserving_field_list(0);
            reg_reset(); 
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
