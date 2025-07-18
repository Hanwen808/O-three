/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parsers.p4"

/* CONSTANTS */
#define BUCKET_NUM 1024
#define cnt_bits 32
#define ID_bits 32
#define seq_bits 32
#define threshold 16
#define PKT_INSTANCE_TYPE_RESUBMIT 6
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
    // First laryer
    register<bit<ID_bits>>(BUCKET_NUM)  ID1;
    register<bit<seq_bits>>(BUCKET_NUM) Seq1;
    register<bit<cnt_bits>>(BUCKET_NUM) Cnt1;
    // operation on ID1
    action ac_read_ID1() {
        ID1.read(meta.ID1_value, hdr.myheader.bucket_index1);
    }

    table tb_read_ID1 {
        actions = {
            ac_read_ID1;
        }
        size = 1;
        const default_action = ac_read_ID1;
    }

    action ac_write_ID1() {
        ID1.write(hdr.myheader.bucket_index1, hdr.ipv4.srcAddr);
    }

    table tb_write_ID1 {
        actions = {
            ac_write_ID1;
        }
        size = 1;
        const default_action = ac_write_ID1;
    }

    // operation on Seq1
    action ac_read_Seq1() {
        Seq1.read(meta.Seq1_value, hdr.myheader.bucket_index1);
    }

    table tb_read_Seq1 {
        actions = {
            ac_read_Seq1;
        }
        size = 1;
        const default_action = ac_read_Seq1;
    }

    action ac_write_Seq1() {
        Seq1.write(hdr.myheader.bucket_index1, hdr.tcp.seqNo);
    }

    table tb_write_Seq1 {
        actions = {
            ac_write_Seq1;
        }
        size = 1;
        const default_action = ac_write_Seq1;
    }

    // operation on Cnt1
    action ac_read_Cnt1() {
        Cnt1.read(meta.Cnt1_value, hdr.myheader.bucket_index1);
    }

    table tb_read_Cnt1 {
        actions = {
            ac_read_Cnt1;
        }
        size = 1;
        const default_action = ac_read_Cnt1;
    }

    action ac_update_Cnt1() {
        Cnt1.write(hdr.myheader.bucket_index1, meta.Cnt1_value + 1);
    }

    table tb_update_Cnt1 {
        actions = {
            ac_update_Cnt1;
        }
        size = 1;
        const default_action = ac_update_Cnt1;
    }

    action ac_clean_Cnt1() {
        Cnt1.write(hdr.myheader.bucket_index1, 0);
    }

    table tb_clean_Cnt1 {
        actions = {
            ac_clean_Cnt1;
        }
        size = 1;
        const default_action = ac_clean_Cnt1;
    }

    // Second laryer
    register<bit<ID_bits>>(BUCKET_NUM)  ID2;
    register<bit<seq_bits>>(BUCKET_NUM) Seq2;
    register<bit<cnt_bits>>(BUCKET_NUM) Cnt2;

    action ac_read_ID2() {
        ID2.read(meta.ID2_value, hdr.myheader.bucket_index2);
    }

    table tb_read_ID2 {
        actions = {
            ac_read_ID2;
        }
        size = 1;
        const default_action = ac_read_ID2;
    }

    action ac_write_ID2() {
        ID2.write(hdr.myheader.bucket_index2, hdr.ipv4.srcAddr);
    }

    table tb_write_ID2 {
        actions = {
            ac_write_ID2;
        }
        size = 1;
        const default_action = ac_write_ID2;
    }

    // operation on Seq2
    action ac_read_Seq2() {
        Seq2.read(meta.Seq2_value, hdr.myheader.bucket_index2);
    }

    table tb_read_Seq2 {
        actions = {
            ac_read_Seq2;
        }
        size = 1;
        const default_action = ac_read_Seq2;
    }

    action ac_write_Seq2() {
        Seq2.write(hdr.myheader.bucket_index2, hdr.tcp.seqNo);
    }

    table tb_write_Seq2 {
        actions = {
            ac_write_Seq2;
        }
        size = 1;
        const default_action = ac_write_Seq2;
    }

    // operation on Cnt1
    action ac_read_Cnt2() {
        Cnt2.read(meta.Cnt2_value, hdr.myheader.bucket_index2);
    }

    table tb_read_Cnt2 {
        actions = {
            ac_read_Cnt2;
        }
        size = 1;
        const default_action = ac_read_Cnt2;
    }

    action ac_update_Cnt2() {
        Cnt2.write(hdr.myheader.bucket_index2, meta.Cnt2_value + 1);
    }

    table tb_update_Cnt2 {
        actions = {
            ac_update_Cnt2;
        }
        size = 1;
        const default_action = ac_update_Cnt2;
    }

    action ac_clean_Cnt2() {
        Cnt2.write(hdr.myheader.bucket_index2, 0);
    }

    table tb_clean_Cnt2 {
        actions = {
            ac_clean_Cnt2;
        }
        size = 1;
        const default_action = ac_clean_Cnt2;
    }

    // Third laryer
    register<bit<ID_bits>>(BUCKET_NUM)  ID3;
    register<bit<seq_bits>>(BUCKET_NUM) Seq3;
    register<bit<cnt_bits>>(BUCKET_NUM) Cnt3;

    action ac_read_ID3() {
        ID3.read(meta.ID3_value, hdr.myheader.bucket_index3);
    }

    table tb_read_ID3 {
        actions = {
            ac_read_ID3;
        }
        size = 1;
        const default_action = ac_read_ID3;
    }

    action ac_write_ID3() {
        ID3.write(hdr.myheader.bucket_index3, hdr.ipv4.srcAddr);
    }

    table tb_write_ID3 {
        actions = {
            ac_write_ID3;
        }
        size = 1;
        const default_action = ac_write_ID3;
    }

    // operation on Seq3
    action ac_read_Seq3() {
        Seq3.read(meta.Seq3_value, hdr.myheader.bucket_index3);
    }

    table tb_read_Seq3 {
        actions = {
            ac_read_Seq3;
        }
        size = 1;
        const default_action = ac_read_Seq3;
    }

    action ac_write_Seq3() {
        Seq3.write(hdr.myheader.bucket_index3, hdr.tcp.seqNo);
    }

    table tb_write_Seq3 {
        actions = {
            ac_write_Seq3;
        }
        size = 1;
        const default_action = ac_write_Seq3;
    }

    // operation on Cnt1
    action ac_read_Cnt3() {
        Cnt3.read(meta.Cnt3_value, hdr.myheader.bucket_index3);
    }

    table tb_read_Cnt3 {
        actions = {
            ac_read_Cnt3;
        }
        size = 1;
        const default_action = ac_read_Cnt3;
    }

    action ac_update_Cnt3() {
        Cnt3.write(hdr.myheader.bucket_index3, meta.Cnt3_value + 1);
    }

    table tb_update_Cnt3 {
        actions = {
            ac_update_Cnt3;
        }
        size = 1;
        const default_action = ac_update_Cnt3;
    }

    action ac_clean_Cnt3() {
        Cnt3.write(hdr.myheader.bucket_index3, 0);
    }

    table tb_clean_Cnt3 {
        actions = {
            ac_clean_Cnt3;
        }
        size = 1;
        const default_action = ac_clean_Cnt3;
    }

    // Last laryer
    register<bit<ID_bits>>(BUCKET_NUM)  ID4;
    register<bit<seq_bits>>(BUCKET_NUM) Seq4;
    register<bit<cnt_bits>>(BUCKET_NUM) Cnt4;

    action ac_read_ID4() {
        ID4.read(meta.ID4_value, hdr.myheader.bucket_index4);
    }

    table tb_read_ID4 {
        actions = {
            ac_read_ID4;
        }
        size = 1;
        const default_action = ac_read_ID4;
    }

    action ac_write_ID4() {
        ID4.write(hdr.myheader.bucket_index4, hdr.ipv4.srcAddr);
    }

    table tb_write_ID4 {
        actions = {
            ac_write_ID4;
        }
        size = 1;
        const default_action = ac_write_ID4;
    }

    // operation on Seq4
    action ac_read_Seq4() {
        Seq4.read(meta.Seq4_value, hdr.myheader.bucket_index4);
    }

    table tb_read_Seq4 {
        actions = {
            ac_read_Seq4;
        }
        size = 1;
        const default_action = ac_read_Seq4;
    }

    action ac_write_Seq4() {
        Seq4.write(hdr.myheader.bucket_index4, hdr.tcp.seqNo);
    }

    table tb_write_Seq4 {
        actions = {
            ac_write_Seq4;
        }
        size = 1;
        const default_action = ac_write_Seq4;
    }

    // operation on Cnt4
    action ac_read_Cnt4() {
        Cnt4.read(meta.Cnt4_value, hdr.myheader.bucket_index4);
    }

    table tb_read_Cnt4 {
        actions = {
            ac_read_Cnt4;
        }
        size = 1;
        const default_action = ac_read_Cnt4;
    }

    action ac_update_Cnt4() {
        Cnt4.write(hdr.myheader.bucket_index4, meta.Cnt4_value + 1);
    }

    table tb_update_Cnt4 {
        actions = {
            ac_update_Cnt4;
        }
        size = 1;
        const default_action = ac_update_Cnt4;
    }

    action ac_clean_Cnt4() {
        Cnt4.write(hdr.myheader.bucket_index4, 0);
    }

    table tb_clean_Cnt4 {
        actions = {
            ac_clean_Cnt4;
        }
        size = 1;
        const default_action = ac_clean_Cnt4;
    }

    action drop() {
        mark_to_drop(standard_metadata);
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
        if (hdr.ipv4.isValid()){
            if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_RESUBMIT) {
                 random(meta.random_number,(bit<8>) 0, (bit<8>) 255);
                 if (hdr.myheader.min_bucket_value > threshold) {
                     meta.temp_res = hdr.myheader.min_seq_num + hdr.tcp.seqNo;
                     meta.temp_res = meta.temp_res * hdr.myheader.min_bucket_value + 1;
                     if ((bit<32>)meta.random_number * meta.temp_res <= 255 * hdr.tcp.seqNo) {
                         if (hdr.myheader.min_row_num == 1) {
                             ID1.write(hdr.myheader.bucket_index1, hdr.ipv4.srcAddr);
                             //tb_write_ID1.apply();
                             tb_clean_Cnt1.apply();
                             //tb_write_Seq1.apply();
                             Seq1.write(hdr.myheader.bucket_index1, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 2) {
                             ID2.write(hdr.myheader.bucket_index2, hdr.ipv4.srcAddr);
                             //tb_write_ID2.apply();
                             tb_clean_Cnt2.apply();
                             //tb_write_Seq2.apply();
                             Seq2.write(hdr.myheader.bucket_index2, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 3) {
                             ID3.write(hdr.myheader.bucket_index3, hdr.ipv4.srcAddr);
                             //tb_write_ID3.apply();
                             tb_clean_Cnt3.apply();
                             //tb_write_Seq3.apply();
                             Seq3.write(hdr.myheader.bucket_index3, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 4) {
                             ID4.write(hdr.myheader.bucket_index4, hdr.ipv4.srcAddr);
                             //tb_write_ID4.apply();
                             tb_clean_Cnt4.apply();
                             //tb_write_Seq4.apply();
                             Seq4.write(hdr.myheader.bucket_index4, hdr.tcp.seqNo);
                         }
                     }
                 } else {
                     meta.temp_res = hdr.myheader.min_bucket_value + 1;
                     if ((bit<32>)meta.random_number * meta.temp_res <= 255) {
                         if (hdr.myheader.min_row_num == 1) {
                             ID1.write(hdr.myheader.bucket_index1, hdr.ipv4.srcAddr);
                             //tb_write_ID1.apply();
                             //tb_clean_Cnt1.apply();
                             Cnt1.write(hdr.myheader.bucket_index1, 0);
                             //tb_write_Seq1.apply();
                             Seq1.write(hdr.myheader.bucket_index1, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 2) {
                             ID2.write(hdr.myheader.bucket_index2, hdr.ipv4.srcAddr);
                             //tb_write_ID2.apply();
                             //tb_clean_Cnt2.apply();
                             Cnt2.write(hdr.myheader.bucket_index2, 0);
                             //tb_write_Seq2.apply();
                             Seq2.write(hdr.myheader.bucket_index2, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 3) {
                             ID3.write(hdr.myheader.bucket_index3, hdr.ipv4.srcAddr);
                             //tb_write_ID3.apply();
                             //tb_clean_Cnt3.apply();
                             Cnt3.write(hdr.myheader.bucket_index3, 0);
                             //tb_write_Seq3.apply();
                             Seq3.write(hdr.myheader.bucket_index3, hdr.tcp.seqNo);
                         }
                         if (hdr.myheader.min_row_num == 4) {
                             ID4.write(hdr.myheader.bucket_index4, hdr.ipv4.srcAddr);
                             //tb_write_ID4.apply();
                             //tb_clean_Cnt4.apply();
                             Cnt4.write(hdr.myheader.bucket_index4, 0);
                             //tb_write_Seq4.apply();
                             Seq4.write(hdr.myheader.bucket_index4, hdr.tcp.seqNo);
                         }
                     }
                 }
            } else {
                 hash(hdr.myheader.bucket_index1, HashAlgorithm.crc32_custom, (bit<16>) 0, {hdr.ipv4.srcAddr}, (bit<32>) BUCKET_NUM);
                 tb_read_ID1.apply();
                 if (meta.ID1_value == 0) {
                     tb_write_ID1.apply();
                     tb_write_Seq1.apply();
                     meta.move_to_next = 0;
                 } else {
                     if (meta.ID1_value == hdr.ipv4.srcAddr) {
                         tb_read_Seq1.apply();
                         if (hdr.tcp.seqNo <= meta.Seq1_value) {
                             tb_update_Cnt1.apply();
                         } else {
                             //tb_write_Seq1.apply();
                             Seq1.write(hdr.myheader.bucket_index1, hdr.tcp.seqNo);
                         }
                         meta.move_to_next = 0;
                     } else {
                         meta.move_to_next = 1;
                     }
                 }
                 // Enter the second laryer
                 if (meta.move_to_next == 1) {
                     hdr.myheader.min_row_num = 1;
                     hdr.myheader.min_bucket_value = meta.Cnt1_value;
                     hdr.myheader.min_seq_num = meta.Seq1_value;
                     tb_read_ID2.apply();
                     if (meta.ID2_value == 0) {
                         tb_write_ID2.apply();
                         tb_write_Seq2.apply();
                         meta.move_to_next = 0;
                     } else {
                         if (meta.ID2_value == hdr.ipv4.srcAddr) {
                             tb_read_Seq2.apply();
                             if (hdr.tcp.seqNo <= meta.Seq2_value) {
                                 tb_update_Cnt2.apply();
                             } else {
                                 //tb_write_Seq2.apply();
                                 Seq2.write(hdr.myheader.bucket_index2, hdr.tcp.seqNo);
                             }
                             meta.move_to_next = 0;
                         } else {
                             meta.move_to_next = 1;
                         }
                     }
                 }
                 // Enter the third laryer
                 if (meta.move_to_next == 1) {
                     if (meta.Cnt2_value < hdr.myheader.min_bucket_value) {
                         hdr.myheader.min_bucket_value = meta.Cnt2_value;
                         hdr.myheader.min_seq_num = meta.Seq2_value;
                         hdr.myheader.min_row_num = 2;
                     }
                     tb_read_ID3.apply();
                     if (meta.ID3_value == 0) {
                         tb_write_ID3.apply();
                         tb_write_Seq3.apply();
                         meta.move_to_next = 0;
                     } else {
                         if (meta.ID3_value == hdr.ipv4.srcAddr) {
                             tb_read_Seq3.apply();
                             if (hdr.tcp.seqNo <= meta.Seq3_value) {
                                 tb_update_Cnt3.apply();
                             } else {
                                 //tb_write_Seq3.apply();
                                 Seq3.write(hdr.myheader.bucket_index3, hdr.tcp.seqNo);
                             }
                             meta.move_to_next = 0;
                         } else {
                             meta.move_to_next = 1;
                         }
                     }
                 }
                 // Enter the last laryer
                 if (meta.move_to_next == 1) {
                     if (meta.Cnt3_value < hdr.myheader.min_bucket_value) {
                         hdr.myheader.min_bucket_value = meta.Cnt3_value;
                         hdr.myheader.min_seq_num = meta.Seq3_value;
                         hdr.myheader.min_row_num = 3;
                     }
                     tb_read_ID4.apply();
                     if (meta.ID4_value == 0) {
                         tb_write_ID4.apply();
                         tb_write_Seq4.apply();
                         meta.move_to_next = 0;
                     } else {
                         if (meta.ID4_value == hdr.ipv4.srcAddr) {
                             tb_read_Seq4.apply();
                             if (hdr.tcp.seqNo <= meta.Seq4_value) {
                                 tb_update_Cnt4.apply();
                             } else {
                                 //tb_write_Seq4.apply();
                                 Seq4.write(hdr.myheader.bucket_index4, hdr.tcp.seqNo);
                             }
                             meta.move_to_next = 0;
                         } else {
                             meta.move_to_next = 1;
                         }
                     }
                 }
                 // Resubmit
                if (meta.move_to_next == 1) {
                    if (meta.Cnt4_value < hdr.myheader.min_bucket_value) {
                        hdr.myheader.min_bucket_value = meta.Cnt4_value;
                        hdr.myheader.min_seq_num = meta.Seq4_value;
                        hdr.myheader.min_row_num = 4;
                    }
                    resubmit({hdr.myheader.min_row_num, hdr.myheader.min_bucket_value, hdr.myheader.min_seq_num});
                }
            }
            forwarding.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

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
