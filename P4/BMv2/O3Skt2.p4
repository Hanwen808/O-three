/* -*- P4_16 -*- */
#include<core.p4>
#if __TARGET_TOFINO__ == 2
#include<t2na.p4>
#else
#include<tna.p4>
#endif

#define M1 1024
#define ID_bits 32
#define seq_bits 32
#define cnt1_bits 32
#define threshold 16

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

struct egress_headers_t {}
struct egress_metadata_t {}

header my_record_h {
    bit<32> bucket_index1;
    bit<32> bucket_index2;
    bit<32> row_num;
    bit<8>  resubmit_flag;
    bit<32> bucket_value1;
    bit<32> bucket_sc_value1;
    bit<32> bucket_value2;
    bit<32> bucket_sc_value2;
    bit<32> bucket_sub_value;
    bit<32> min_seq_value;
    bit<8>  final_update_tag;
    bit<32> cond_size;
    bit<32> cond_size12;
    bit<32> cond_min_seq;
    bit<32> cond_arr_seq;
    bit<32> cond_sum_seq;
    bit<8>  small_tag;
    bit<32> right_shift_fen_zi;
    bit<32> right_shift_fen_zi2;
    bit<32> cond2;
}

struct metadata{
    bit<8> key_cmp_flag1;
    bit<8> key_cmp_flag2;
    bit<32> seq_value1;
    bit<32> seq_value2;
    bit<32> diff_seq;
    bit<32> min_value;
    bit<32> diff_bucket_value;
    bit<8>  random_number;
    bit<32> cond;
    bit<32> cond12;
    bit<32> cond2;
    bit<32> diff_threshold;
    bit<8>  update_flag;
    bit<8>  update_flag2;
    bit<32> right_shift_arr_seq;
    bit<32> right_shift_min_seq;
    bit<32> right_shift_fen_mu;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_h        tcp;
	my_record_h myrecord;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
@pa_atomic("ingress", "meta.random_number")
@pa_atomic("ingress", "meta.cond")
@pa_atomic("ingress", "hdr.myrecord.cond_size")
@pa_atomic("ingress", "hdr.myrecord.cond_min_seq")
@pa_atomic("ingress", "hdr.myrecord.cond_arr_seq")
@pa_atomic("ingress", "hdr.myrecord.cond_sum_seq")
parser MyParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
    }
	
	state parse_ethernet {
		packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
	}
	
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol)
        {
            (bit<8>) 17 : parse_tcp;
            default : accept;
        }
    }

    state parse_tcp {
		packet.extract(hdr.tcp);
		transition parse_myflow;
	}

	state parse_myflow {
		transition select(ig_intr_md.resubmit_flag) {
			0: parse_origin;
			1: parse_resubmit;
		}
	}

	state parse_origin {
		hdr.myrecord.setValid();
		transition accept;
	}
	
	state parse_resubmit {
		packet.extract(hdr.myrecord);
		transition accept;
	}

}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  in ingress_intrinsic_metadata_t ig_intr_md,
				  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
				  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
				  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
					) {
	/*
    * the flow key is selected as source IP address
    */
	Register<bit<ID_bits>, bit<32>>(M1) level1_ID;
    Register<bit<seq_bits>, bit<32>>(M1) level1_seq;
    Register<bit<cnt1_bits>, bit<32>>(M1) level1_cnt;
    Register<bit<cnt1_bits>, bit<32>>(M1) level1_cnts;
    Register<bit<ID_bits>, bit<32>>(M1) level2_ID;
    Register<bit<seq_bits>, bit<32>>(M1) level2_seq;
    Register<bit<cnt1_bits>, bit<32>>(M1) level2_cnt;
    Register<bit<cnt1_bits>, bit<32>>(M1) level2_cnts;

	CRCPolynomial<bit<32>>(coeff=0x04C11DB7,reversed=true, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc_level1;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc_level1) hash_level1;
	CRCPolynomial<bit<32>>(coeff=0xF23D4780,reversed=true, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc_level2;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc_level2) hash_level2;
	
	action ac_get_hash_value_level1() {
		hdr.myrecord.bucket_index1 = (bit<32>) hash_level1.get({hdr.ipv4.srcAddr})[9:0];
	}

	table tb_get_hash_value_level1 {
		actions = {
			ac_get_hash_value_level1;
		}
		size = 1;
		default_action = ac_get_hash_value_level1;
	}
	
	action ac_get_hash_value_level2() {
		hdr.myrecord.bucket_index2 = (bit<32>) hash_level2.get({hdr.ipv4.srcAddr})[9:0];
	}

	table tb_get_hash_value_level2 {
		actions = {
			ac_get_hash_value_level2;
		}
		size = 1;
		const default_action = ac_get_hash_value_level2;
	}

    RegisterAction<bit<ID_bits>, bit<32>, bit<ID_bits>>(level1_ID) level1_ID_check_value = {
		void apply(inout bit<ID_bits> register_data, out bit<ID_bits> result) {
			if (register_data == 0) {
                register_data = hdr.ipv4.srcAddr;
                result = 0;
            } else {
                if (register_data == hdr.ipv4.srcAddr) {
                    result = 0;
                } else {
                    result = 1;
                }
            }
		}
	};

    action ac_level1_ID_check_value() {
        meta.key_cmp_flag1 = (bit<8>) level1_ID_check_value.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_ID_check_value {
        actions = {
            ac_level1_ID_check_value;
        }
        size = 1;
        const default_action = ac_level1_ID_check_value;
    }

    RegisterAction<bit<ID_bits>, bit<32>, bit<ID_bits>>(level1_ID) level1_set_ID = {
		void apply(inout bit<ID_bits> register_data, out bit<ID_bits> result) {
            register_data = hdr.ipv4.srcAddr;
            result = register_data;
		}
	};

    action ac_level1_set_ID() {
        level1_set_ID.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_set_ID {
        actions = {
            ac_level1_set_ID;
        }
        size = 1;
        const default_action = ac_level1_set_ID;
    }

    RegisterAction<bit<seq_bits>, bit<32>, bit<seq_bits>>(level1_seq) level1_seq_check_value = {
		void apply(inout bit<seq_bits> register_data, out bit<seq_bits> result) {
            if (meta.key_cmp_flag1 == 0) {
                if (register_data < hdr.tcp.seq_no) {
                    register_data = hdr.tcp.seq_no;
                }
                result = register_data;
            } else {
                result = register_data;
            }
		}
	};

    action ac_level1_seq_check_value() {
        meta.seq_value1 = (bit<32>) level1_seq_check_value.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_seq_check_value {
        actions = {
            ac_level1_seq_check_value;
        }
        size = 1;
        const default_action = ac_level1_seq_check_value;
    }

    RegisterAction<bit<seq_bits>, bit<32>, bit<seq_bits>>(level1_seq) level1_set_seq = {
		void apply(inout bit<seq_bits> register_data, out bit<seq_bits> result) {
            register_data = hdr.tcp.seq_no;
            result = register_data;
		}
	};

    action ac_level1_set_seq() {
        level1_set_seq.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_set_seq {
        actions = {
            ac_level1_set_seq;
        }
        size = 1;
        const default_action = ac_level1_set_seq;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level1_cnt) level1_cnt_update_value = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = register_data + 1;
			result = register_data;
		}
	};

    action ac_level1_cnt_update_value() {
        hdr.myrecord.bucket_value1 = level1_cnt_update_value.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_cnt_update_value {
        actions = {
            ac_level1_cnt_update_value;
        }
        size = 1;
        const default_action = ac_level1_cnt_update_value;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level1_cnt) level1_set_cnt = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = 0;
            result = register_data;
		}
	};

    action ac_level1_set_cnt() {
        level1_set_cnt.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_set_cnt {
        actions = {
            ac_level1_set_cnt;
        }
        size = 1;
        const default_action = ac_level1_set_cnt;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level1_cnts) level1_cnts_update_value = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = register_data + 1;
			result = register_data;
		}
	};

    action ac_level1_cnts_update_value() {
        hdr.myrecord.bucket_sc_value1 = level1_cnts_update_value.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_cnts_update_value {
        actions = {
            ac_level1_cnts_update_value;
        }
        size = 1;
        const default_action = ac_level1_cnts_update_value;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level1_cnts) level1_set_cnts = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = 0;
            result = register_data;
		}
	};

    action ac_level1_set_cnts() {
        level1_set_cnts.execute(hdr.myrecord.bucket_index1);
    }

    table tb_level1_set_cnts {
        actions = {
            ac_level1_set_cnts;
        }
        size = 1;
        const default_action = ac_level1_set_cnts;
    }

    /**Level 2**/
    RegisterAction<bit<ID_bits>, bit<32>, bit<ID_bits>>(level2_ID) level2_ID_check_value = {
		void apply(inout bit<ID_bits> register_data, out bit<ID_bits> result) {
			if (register_data == 0) {
                register_data = hdr.ipv4.srcAddr;
                result = 0;
            } else {
                if (register_data == hdr.ipv4.srcAddr) {
                    result = 0;
                } else {
                    result = 1;
                }
            }
		}
	};

    action ac_level2_ID_check_value() {
        meta.key_cmp_flag2 = (bit<8>) level2_ID_check_value.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_ID_check_value {
        actions = {
            ac_level2_ID_check_value;
        }
        size = 1;
        const default_action = ac_level2_ID_check_value;
    }

    RegisterAction<bit<ID_bits>, bit<32>, bit<ID_bits>>(level2_ID) level2_set_ID = {
		void apply(inout bit<ID_bits> register_data, out bit<ID_bits> result) {
            register_data = hdr.ipv4.srcAddr;
            result = register_data;
		}
	};

    action ac_level2_set_ID() {
        level2_set_ID.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_set_ID {
        actions = {
            ac_level2_set_ID;
        }
        size = 1;
        const default_action = ac_level2_set_ID;
    }

    RegisterAction<bit<seq_bits>, bit<32>, bit<seq_bits>>(level2_seq) level2_seq_check_value = {
		void apply(inout bit<seq_bits> register_data, out bit<seq_bits> result) {
            if (meta.key_cmp_flag2 == 0) {
                if (register_data < hdr.tcp.seq_no) {
                    register_data = hdr.tcp.seq_no;
                }
                result = register_data;
            } else {
                result = register_data;
            }
		}
	};

    action ac_level2_seq_check_value() {
        meta.seq_value2 = (bit<32>) level2_seq_check_value.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_seq_check_value {
        actions = {
            ac_level2_seq_check_value;
        }
        size = 1;
        const default_action = ac_level2_seq_check_value;
    }

    RegisterAction<bit<seq_bits>, bit<32>, bit<seq_bits>>(level2_seq) level2_set_seq = {
		void apply(inout bit<seq_bits> register_data, out bit<seq_bits> result) {
            register_data = hdr.tcp.seq_no;
            result = register_data;
		}
	};

    action ac_level2_set_seq() {
        level2_set_seq.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_set_seq {
        actions = {
            ac_level2_set_seq;
        }
        size = 1;
        const default_action = ac_level2_set_seq;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level2_cnt) level2_cnt_update_value = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = register_data + 1;
			result = register_data;
		}
	};

    action ac_level2_cnt_update_value() {
        hdr.myrecord.bucket_value2 = level2_cnt_update_value.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_cnt_update_value {
        actions = {
            ac_level2_cnt_update_value;
        }
        size = 1;
        const default_action = ac_level2_cnt_update_value;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level2_cnt) level2_set_cnt = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = 0;
            result = register_data;
		}
	};

    action ac_level2_set_cnt() {
        level2_set_cnt.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_set_cnt {
        actions = {
            ac_level2_set_cnt;
        }
        size = 1;
        const default_action = ac_level2_set_cnt;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level2_cnts) level2_cnts_update_value = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = register_data + 1;
			result = register_data;
		}
	};

    action ac_level2_cnts_update_value() {
        hdr.myrecord.bucket_sc_value2 = level2_cnts_update_value.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_cnts_update_value {
        actions = {
            ac_level2_cnts_update_value;
        }
        size = 1;
        const default_action = ac_level2_cnts_update_value;
    }

    RegisterAction<bit<cnt1_bits>, bit<32>, bit<cnt1_bits>>(level2_cnts) level2_set_cnts = {
		void apply(inout bit<cnt1_bits> register_data, out bit<cnt1_bits> result) {
            register_data = 0;
            result = register_data;
		}
	};

    action ac_level2_set_cnts() {
        level2_set_cnts.execute(hdr.myrecord.bucket_index2);
    }

    table tb_level2_set_cnts {
        actions = {
            ac_level2_set_cnts;
        }
        size = 1;
        const default_action = ac_level2_set_cnts;
    }

    action ac_set_min_row_num_to_1() {
        hdr.myrecord.row_num = 1;
    }

    table tb_set_min_row_num_to_1 {
        actions = {
            ac_set_min_row_num_to_1;
        }
        size = 1;
        const default_action = ac_set_min_row_num_to_1;
    }

    action ac_set_min_row_num_to_2() {
        hdr.myrecord.row_num = 2;
    }

    table tb_set_min_row_num_to_2 {
        key = {
            meta.diff_bucket_value : ternary;
        }
        actions = {
            ac_set_min_row_num_to_2;
            NoAction;
        }
        size = 8;
        const default_action = NoAction;
        const entries = {
            0x80000000 &&& 0x80000000 : ac_set_min_row_num_to_2;
        }
    }

    action ac_get_diff_between_buckets() {
        meta.diff_bucket_value = hdr.myrecord.bucket_value2 - hdr.myrecord.bucket_value1;
    }

    table tb_get_diff_between_buckets {
        actions = {
            ac_get_diff_between_buckets;
        }
        size = 1;
        const default_action = ac_get_diff_between_buckets;
    }

    action ac_set_resubmit_flag() {
        hdr.myrecord.resubmit_flag = 1;
    }

    table tb_set_resubmit_flag {
        actions = {
            ac_set_resubmit_flag;
        }
        size = 1;
        const default_action = ac_set_resubmit_flag;
    }

    Random<bit<8>>() rng;

    action ac_get_random_256() {
        meta.random_number = rng.get();
    }

    table tb_get_random_256 {
        actions = {
            ac_get_random_256;
        }
        size = 1;
        const default_action = ac_get_random_256;
    }

    action calc_cond(){
		meta.cond = (bit<32>) meta.random_number - hdr.myrecord.cond_size;
	}

	table calc_cond_table{
		actions = {
			calc_cond;
		}
		size = 1;
		const default_action = calc_cond();
	}

    action calc_cond12(){
		meta.cond12 = (bit<32>) meta.random_number - hdr.myrecord.cond_size12;
	}

	table calc_cond12_table{
		actions = {
			calc_cond12;
		}
		size = 1;
		const default_action = calc_cond12();
	}

    action ac_calc_cond_rng_min_seq(){
		hdr.myrecord.cond2 = (bit<32>) meta.random_number - hdr.myrecord.cond_min_seq;
	}

	table tb_calc_cond_rng_min_seq {
		actions = {
			ac_calc_cond_rng_min_seq;
		}
		size = 1;
		const default_action = ac_calc_cond_rng_min_seq();
	}

    action ac_calc_cond_rng_arr_seq(){
		meta.cond2 = (bit<32>) meta.random_number - hdr.myrecord.cond_arr_seq;
	}

	table tb_calc_cond_rng_arr_seq {
		actions = {
			ac_calc_cond_rng_arr_seq;
		}
		size = 1;
		const default_action = ac_calc_cond_rng_arr_seq();
	}

    action ac_calc_cond_rng_sum_seq(){
		meta.cond2 = (bit<32>) meta.random_number - hdr.myrecord.cond_sum_seq;
	}

	table tb_calc_cond_rng_sum_seq {
		actions = {
			ac_calc_cond_rng_sum_seq;
		}
		size = 1;
		const default_action = ac_calc_cond_rng_sum_seq();
	}

    action ac_set_min_val_bucket1() {
        meta.min_value = hdr.myrecord.bucket_value1;
    }

    table tb_set_min_val_bucket1{
        actions = {
            ac_set_min_val_bucket1;
        }
        size = 1;
        const default_action = ac_set_min_val_bucket1;
    }

	/*
		Basic forwarding
	*/
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
	
    action ipv4_forward(egressSpec_t port) {
	    ig_tm_md.ucast_egress_port = port;
    }
	
    table ipv4_lpm {
        key = {
		    hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 32;

        default_action = NoAction();
    }

    action ac_get_diff_rec_arr_seq1() {
        meta.diff_seq = meta.seq_value1 - hdr.tcp.seq_no;
    }

    table tb_get_diff_rec_arr_seq1 {
        actions = {
            ac_get_diff_rec_arr_seq1;
        }
        size = 1;
        const default_action = ac_get_diff_rec_arr_seq1;
    }

    action ac_get_diff_rec_arr_seq2() {
        meta.diff_seq = meta.seq_value2 - hdr.tcp.seq_no;
    }

    table tb_get_diff_rec_arr_seq2 {
        actions = {
            ac_get_diff_rec_arr_seq2;
        }
        size = 1;
        const default_action = ac_get_diff_rec_arr_seq2;
    }

    action ac_set_min_seq_value1() {
        hdr.myrecord.min_seq_value = meta.seq_value1;
    }

    table tb_set_min_seq_value1 {
        actions = {
            ac_set_min_seq_value1;
        }
        size = 1;
        const default_action = ac_set_min_seq_value1;
    }

    action ac_get_diff_min_arr_seq() {
        meta.diff_seq = hdr.myrecord.min_seq_value - hdr.tcp.seq_no;
    }

    table tb_get_diff_min_arr_seq {
        actions = {
            ac_get_diff_min_arr_seq;
        }
        size = 1;
        const default_action = ac_get_diff_min_arr_seq;
    }

    action ac_cmp_cnt_threshold() {
        meta.diff_threshold = hdr.myrecord.bucket_value1 - threshold;
    }

    table tb_cmp_cnt_threshold {
        actions = {
            ac_cmp_cnt_threshold;
        }
        size = 1;
        const default_action = ac_cmp_cnt_threshold;
    }

/***********************************************************************/

Register<bit<32>,bit<1>>(1) num_32_bucket1;

    MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_mu1;

    RegisterAction<bit<32>,bit<1>,bit<32>>(num_32_bucket1) prog_64K_div_x1 = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_mu1.execute(hdr.myrecord.bucket_value1);
            mau_value = register_data;
		}
	};
	
	action calc_cond_pre1(){
		hdr.myrecord.cond_size = prog_64K_div_x1.execute(0);
	}

    table tb_calc_cond_pre1 {
        actions = {
            calc_cond_pre1;
        }
        size = 1;
        const default_action = calc_cond_pre1;
    }

    action ac_sub_b1_to_b2() {
        hdr.myrecord.bucket_sub_value = hdr.myrecord.bucket_value1 |-| hdr.myrecord.bucket_sc_value1;
    }

    table tb_sub_b1_to_b2 {
        actions = {
            ac_sub_b1_to_b2;
        }
        size = 1;
        const default_action = ac_sub_b1_to_b2;
    }

    Register<bit<32>,bit<1>>(1) num_32_bucket12;
    MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_mu12;

    RegisterAction<bit<32>,bit<1>,bit<32>>(num_32_bucket12) prog_64K_div_x12 = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_mu12.execute(hdr.myrecord.bucket_sub_value);
            mau_value = register_data;
		}
	};

    action calc_cond_pre12(){
		hdr.myrecord.cond_size = prog_64K_div_x12.execute(0);
	}

    table tb_calc_cond_pre12 {
        actions = {
            calc_cond_pre12;
        }
        size = 1;
        const default_action = calc_cond_pre12;
    }

    Register<bit<32>,bit<1>>(1) num_32_min_seq;

    MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_min_seq;

    RegisterAction<bit<32>,bit<1>,bit<32>>(num_32_min_seq) rg_prog_64K_div_min_seq = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_min_seq.execute(hdr.myrecord.min_seq_value);
            mau_value = register_data;
		}
	};
	
	action calc_cond_min_seq() {
		hdr.myrecord.cond_min_seq = rg_prog_64K_div_min_seq.execute(0);
	}

    table tb_calc_cond_min_seq {
        actions = {
            calc_cond_min_seq;
        }
        size = 1;
        const default_action = calc_cond_min_seq;
    }

    Register<bit<32>,bit<1>>(1) num_32_arr_seq;

    MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_arr_seq;

    RegisterAction<bit<32>,bit<1>,bit<32>>(num_32_arr_seq) rg_prog_64K_div_arr_seq = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_arr_seq.execute(hdr.tcp.seq_no);
            mau_value = register_data;
		}
	};
	
	action calc_cond_arr_seq() {
		hdr.myrecord.cond_arr_seq = rg_prog_64K_div_arr_seq.execute(0);
	}

    table tb_calc_cond_arr_seq {
        actions = {
            calc_cond_arr_seq;
        }
        size = 1;
        const default_action = calc_cond_arr_seq;
    }

    Register<bit<32>,bit<1>>(1) num_32_sum_seq;

    MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_sum_seq;

    RegisterAction<bit<32>,bit<1>,bit<32>>(num_32_sum_seq) rg_prog_64K_div_sum_seq = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_min_seq.execute(meta.right_shift_fen_mu);
            mau_value = register_data;
		}
	};
	
	action calc_cond_sum_seq() {
		hdr.myrecord.cond_sum_seq = rg_prog_64K_div_sum_seq.execute(0);
	}

    table tb_calc_cond_sum_seq {
        actions = {
            calc_cond_sum_seq;
        }
        size = 1;
        const default_action = calc_cond_sum_seq;
    }

/***********************************************************************/

    action ac_add_min_arr_seq() {
        meta.right_shift_fen_mu = meta.right_shift_min_seq + meta.right_shift_arr_seq;
    }

    table tb_add_min_arr_seq {
        actions = {
            ac_add_min_arr_seq;
        }
        size = 1;
        const default_action = ac_add_min_arr_seq;
    }

    action ac_diff_fen_zi_mu() {
        hdr.myrecord.right_shift_fen_zi2 =  hdr.myrecord.right_shift_fen_zi2 -  meta.right_shift_min_seq; //meta.right_shift_fen_mu;
    }

    table tb_diff_fen_zi_mu {
        actions = {
            ac_diff_fen_zi_mu;
        }
        size = 1;
        const default_action = ac_diff_fen_zi_mu;
    }

    action ac_diff_arr_min_seq() {
        hdr.myrecord.right_shift_fen_zi2 = hdr.tcp.seq_no - hdr.myrecord.min_seq_value;
    }

    table tb_diff_arr_min_seq {
        actions = {
            ac_diff_arr_min_seq;
        }
        size = 1;
        const default_action = ac_diff_arr_min_seq;
    }

    apply {
        //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
        if (hdr.ipv4.isValid()){
            if(ig_intr_md.resubmit_flag == 0){
                //hdr.myrecord.right_shift_fen_zi = hdr.tcp.seq_no >> 17;
                //hdr.myrecord.right_shift_fen_zi2 = hdr.tcp.seq_no >> 16;
                tb_get_hash_value_level1.apply();
                tb_get_hash_value_level2.apply();
                tb_level1_ID_check_value.apply();
                tb_level1_seq_check_value.apply();
                tb_get_diff_rec_arr_seq1.apply();
                if (meta.key_cmp_flag1 == 0) {
                    if (meta.diff_seq < 0x80000000) {
                        tb_level1_cnt_update_value.apply();
                    } else {
                        tb_level1_cnts_update_value.apply();
                    }
                } else {
                    tb_set_min_val_bucket1.apply();
                    tb_set_min_row_num_to_1.apply();
                    tb_set_min_seq_value1.apply();
                    tb_level2_ID_check_value.apply();
                    tb_level2_seq_check_value.apply();
                    tb_get_diff_rec_arr_seq2.apply();
                    if (meta.key_cmp_flag2 == 0) {
                        if (meta.diff_seq < 0x80000000) {
                            tb_level2_cnt_update_value.apply();
                        } else {
                            tb_level2_cnts_update_value.apply();
                        }
                    } else {
                        tb_get_diff_between_buckets.apply();
                        tb_set_min_row_num_to_2.apply();
                        if (hdr.myrecord.row_num == 2) {
                            hdr.myrecord.bucket_value1 = hdr.myrecord.bucket_value2;
                            hdr.myrecord.min_seq_value = meta.seq_value2;
                        }
                        tb_get_random_256.apply();
                        if (hdr.myrecord.bucket_value1 < 2) {
                            tb_calc_cond_pre1.apply();
                        } else {
                            tb_sub_b1_to_b2.apply();
                            tb_calc_cond_pre12.apply();
                        }
                        calc_cond_table.apply();
                        if (meta.cond < 256) {
                            hdr.myrecord.resubmit_flag = 1;
                        }
                    }
                }
            } else {
                if (hdr.myrecord.resubmit_flag == 1) {
                    hdr.myrecord.resubmit_flag = 0;
                    if (hdr.myrecord.row_num == 1) {
                        tb_level1_set_ID.apply();
                        tb_level1_set_seq.apply();
                        tb_level1_set_cnt.apply();
                        tb_level1_set_cnts.apply();
                    } else {
                        tb_level2_set_ID.apply();
                        tb_level2_set_seq.apply();
                        tb_level2_set_cnt.apply();
                        tb_level2_set_cnts.apply();
                    }
                }
            }
			ipv4_lpm.apply();
        }
    }
}

control IngressDeparser(packet_out packet,
	inout headers hdr,
	in metadata meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
	Resubmit() resubmit;

	apply{
		if(hdr.myrecord.resubmit_flag == 1) {
			resubmit.emit();
		} 
		packet.emit(hdr);
	}
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser EgressParser(packet_in packet,
	out egress_headers_t hdr,
	out egress_metadata_t meta,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start{
		packet.extract(eg_intr_md);
		transition accept;
	}
}

control Egress(inout egress_headers_t hdr,
				inout egress_metadata_t meta,
				in egress_intrinsic_metadata_t eg_intr_md,
				in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
				inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
				inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) 
{
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control EgressDeparser(packet_out packet, 
						inout egress_headers_t hdr, 
						in egress_metadata_t meta, 
						in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        //parsed headers have to be added again into the packet.
		packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
Pipeline(
MyParser(),
MyIngress(),
IngressDeparser(),
EgressParser(),
Egress(),
EgressDeparser()
) pipe;

Switch(pipe) main;