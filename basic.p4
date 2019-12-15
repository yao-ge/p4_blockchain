/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<552>  data_string = 0x5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/



// 'i', 'r','w','j', 'e', 'd' 
#define INIT_REQUEST_L  0x69
#define INIT_REQUEST_U  0x49
#define READ_REQUEST_L  0x72
#define READ_REQUEST_U  0x52
#define WRITE_REQUEST_L 0x77
#define WRITE_REQUEST_U 0x57
#define JOIN_REQUEST_L  0x6A
#define JOIN_REQUEST_U  0x4A
#define EXIT_REQUEST_L  0x65
#define EXIT_REQUEST_U  0x45
#define DROP_REQUEST_L  0x64
#define DROP_REQUEST_U  0x44

#define HEADER_HASH_ZERO_COUNT 4

#define MAX_NODES 10
#define SINGLE_NODE_BLOCK_COUNT 1024
#define NODE_SEQ(in_port) (in_port >> 1) - 1    // max = 9, begin from 0
#define BLOCK_LIST_INDEX(node_seq, b_count) (node_seq * SINGLE_NODE_BLOCK_COUNT) + b_count    // max = MAX_NODES * SINGLE_NODE_BLOCK_COUNT
#define BLOCK_HEADER_HASH_LIST_INDEX(node_seq, b_count) (node_seq * SINGLE_NODE_BLOCK_COUNT) + b_count    // max = MAX_NODES * SINGLE_NODE_BLOCK_COUNT

#define FAKE_SHA256(input_data)    0x011111111111111111111111111111111111111111111111111111111111111F

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

header udp_t {
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   length;
    bit<16>   checksum;
	bit<8>    request_type;
	bit<256>  header_hash;
	bit<552>  data;
}


struct block_metadata_t {
	bit<256>  curr_header_hash;
	bit<256>  pre_header_hash;
	bit<256>  data_hash;
	bit<32>   timestamp;
	bit<32>   nonce;
	bit<552>  data;

	bit<32>   node_seq;
	bit<32>   bl_index;
	bit<32>   bh_index;
}

struct metadata {
	/* empty */
	block_metadata_t block_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	udp_t        udp;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_udp;
    }

	state parse_udp {
		packet.extract(hdr.udp);
		transition accept;
	}

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
************   R E G I S T E R   *****************************************
*************************************************************************/


//register<bit<1>>(1) re_count;

// max node num 10, each node has 1024 block
register<bit<1128>>(MAX_NODES * SINGLE_NODE_BLOCK_COUNT)  block_list;                      // save block 
register<bit<256>>(MAX_NODES * SINGLE_NODE_BLOCK_COUNT)   curr_block_header_hash_list;     // save header hash of block
register<bit<32>>(MAX_NODES)							  block_count;					   // indicate block count of each node
register<bit<32>>(MAX_NODES)   							  done_list;					   // record the block index who has finished proof of work
register<bit<32>>(1)									  proof_of_work_done;		   	   // indicate node has finish proof of work
register<bit<32>>(1)        							  done_count;					   // count of node done proof of work
register<bit<32>>(1)									  done_index;					   // index of done register, begin from zero. for verify
register<bit<32>>(1)        							  verify_failed_count;			   // indicate verify failed node count
register<bit<32>>(1)									  verify_success_count;			   // indicate verify success node count 
register<bit<32>>(1)        							  nodes_count;                     // total nodes count


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

	action multicast(){
		standard_metadata.mcast_grp = 1;
	}

	action change_egress_port(){
		if(standard_metadata.ingress_port == 1){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 1;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 3){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 3;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 5){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 5;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 7){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 7;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 9){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 9;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 11){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 11;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 13){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 13;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 15){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 15;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 17){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 17;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 19){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 19;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 21){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 21;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}
	}

	action polling_packet(){
		if(standard_metadata.ingress_port == 1){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 1;
			standard_metadata.egress_port = 2;
			standard_metadata.egress_spec = 2;
		}else if(standard_metadata.ingress_port == 3){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 3;
			standard_metadata.egress_port = 4;
			standard_metadata.egress_spec = 4;
		}else if(standard_metadata.ingress_port == 5){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 5;
			standard_metadata.egress_port = 6;
			standard_metadata.egress_spec = 6;
		}else if(standard_metadata.ingress_port == 7){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 7;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}
	}

	action change_request_type() {
		bit<8> tmp;
		tmp = hdr.udp.request_type;
		tmp = DROP_REQUEST_L;
		hdr.udp.request_type = tmp;
	}

	action get_timestamp() {
		meta.block_metadata.timestamp = standard_metadata.ingress_global_timestamp[31:0];
	}

	action get_random(){
		random(meta.block_metadata.nonce, 0, 4294967295);
	}

	action get_request_type(){
		if (hdr.udp.request_type == READ_REQUEST_L){
			hdr.udp.request_type = READ_REQUEST_U;
		}else if(hdr.udp.request_type == READ_REQUEST_U){
			hdr.udp.request_type = READ_REQUEST_L;
		}else if(hdr.udp.request_type == WRITE_REQUEST_L){
			hdr.udp.request_type = WRITE_REQUEST_U;
		}else if(hdr.udp.request_type == WRITE_REQUEST_U){
			hdr.udp.request_type = WRITE_REQUEST_L;
		}else if(hdr.udp.request_type == JOIN_REQUEST_L){
			hdr.udp.request_type = JOIN_REQUEST_U;
		}else if(hdr.udp.request_type == JOIN_REQUEST_U){
			hdr.udp.request_type = JOIN_REQUEST_L;
		}
	}

	action get_node_seq_bl_bh_index(){
		bit<32> b_count = 0;

		meta.block_metadata.node_seq[8:0] = NODE_SEQ(standard_metadata.ingress_port);
		block_count.read(b_count, meta.block_metadata.node_seq);
		meta.block_metadata.bl_index = BLOCK_LIST_INDEX(meta.block_metadata.node_seq, b_count);
		meta.block_metadata.bh_index = BLOCK_HEADER_HASH_LIST_INDEX(meta.block_metadata.node_seq, b_count);
	}

	action init_block_count(){
		bit<32> count = 0;

		//get_node_seq_bl_bh_index();
		//block_count.write(meta.block_metadata.node_seq, 0);
		block_count.write(0, 0);
		block_count.write(1, 0);
		block_count.write(2, 0);
		block_count.write(3, 0);
		block_count.write(4, 0);
		block_count.write(5, 0);
		block_count.write(6, 0);
		block_count.write(7, 0);
		block_count.write(8, 0);
		block_count.write(9, 0);
	}

	action add_block_count(bit<32> b_index, bit<32> count){
		bit<32> tmp = 0;

		//get_node_seq_bl_bh_index();
		block_count.read(tmp, b_index);
		tmp = tmp + count;
		block_count.write(b_index, tmp);
	}

	action add_block_to_list(){
		bit<1128> tmp = 0;
		tmp[255:0] = meta.block_metadata.pre_header_hash;
		tmp = tmp << 256;
		tmp[255:0] = meta.block_metadata.data_hash;
		tmp = tmp << 32;
		tmp[31:0] = meta.block_metadata.timestamp;
		tmp = tmp << 32;
		tmp[31:0] = meta.block_metadata.nonce;
		tmp = tmp << 256;
		tmp = tmp << 256;
		tmp = tmp << 40;
		tmp[551:0] = meta.block_metadata.data;

		get_node_seq_bl_bh_index();

		block_list.write(meta.block_metadata.bl_index, tmp);
		curr_block_header_hash_list.write(meta.block_metadata.bh_index, meta.block_metadata.curr_header_hash);
		add_block_count(meta.block_metadata.node_seq, 1);
		hdr.udp.header_hash = meta.block_metadata.curr_header_hash;
	}

	action read_header_hash_from_list(){
		bit<256> tmp = 0;

		get_node_seq_bl_bh_index();
		curr_block_header_hash_list.read(tmp, meta.block_metadata.bh_index - 1);
		hdr.udp.header_hash = tmp;
		meta.block_metadata.pre_header_hash = tmp;
	}

	action read_block_from_list(){
		bit<1128> tmp = 0;
		
		get_node_seq_bl_bh_index();
		block_list.read(tmp, meta.block_metadata.bl_index - 1);

		meta.block_metadata.pre_header_hash = tmp[1127:872];
		meta.block_metadata.data_hash = tmp[871:616];
		meta.block_metadata.timestamp = tmp[615:584];
		meta.block_metadata.nonce = tmp[583:552];
		meta.block_metadata.data = tmp[551:0];

		read_header_hash_from_list();
	}

	action construct_genesis_block(){
		meta.block_metadata.pre_header_hash = 65535;
		meta.block_metadata.data = data_string;
		meta.block_metadata.data_hash = FAKE_SHA256(meta.block_metadata.data);
		meta.block_metadata.timestamp = 0;
		meta.block_metadata.nonce = 0;
		meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		add_block_to_list();
	}

	action construct_new_block() {
		read_block_from_list();
		meta.block_metadata.pre_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		meta.block_metadata.data = data_string;
		meta.block_metadata.data_hash = FAKE_SHA256(meta.block_metadata.data);
		get_timestamp();
		get_random();
		meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		add_block_to_list();
	}

	action init_proof_of_work_register(){
		done_list.write(0, 0);
		done_list.write(1, 0);
		done_list.write(2, 0);
		done_list.write(3, 0);
		done_list.write(4, 0);
		done_list.write(5, 0);
		done_list.write(6, 0);
		done_list.write(7, 0);
		done_list.write(8, 0);
		done_list.write(9, 0);
		done_count.write(0, 0);
		done_index.write(0, 0);
		proof_of_work_done.write(0, 0);
		verify_failed_count.write(0, 0);
		verify_success_count.write(0, 0);
	}

	action add_done_count(){
		bit<32> tmp = 0;
		done_count.read(tmp, 0);
		tmp = tmp + 1;
		done_count.write(0, tmp);
	}

	action add_done_index(){
		bit<32> tmp = 0;
		done_index.read(tmp, 0);
		tmp = tmp + 1;
		done_index.write(0, tmp);
	}

	action set_proof_of_work_register(){
		bit<32> d_count = 0;
		bit<32> tmp = 0;
		done_count.read(d_count, 0);
		get_node_seq_bl_bh_index();

		done_list.write(d_count, meta.block_metadata.bl_index);

		proof_of_work_done.read(tmp, 0);
		tmp = tmp | (32w1 << (bit<8>)meta.block_metadata.node_seq);
		proof_of_work_done.write(0, tmp);
		add_done_count();
	}

	action init_nodes_count(){
		nodes_count.write(0, 2);
	}

	action add_nodes_count(){
		bit<32> tmp = 0;
		nodes_count.read(tmp, 0);
		tmp = tmp + 1;
		nodes_count.write(0, tmp);
	}

	action add_verify_success_count(){
		bit<32> tmp = 0;
		verify_success_count.read(tmp, 0);
		tmp = tmp + 1;
		verify_success_count.write(0, tmp);
	}

	action add_verify_failed_count(){
		bit<32> tmp = 0;
		verify_failed_count.read(tmp, 0);
		tmp = tmp + 1;
		verify_failed_count.write(0, tmp);
	}

	action verify_block(){
		bit<1128> tmp = 0;
		bit<32>   bl_count = 0;
		bit<32>   d_index = 0;

		done_index.read(d_index, 0);

		done_list.read(bl_count, d_index);

		block_list.read(tmp, bl_count - 1);

		meta.block_metadata.pre_header_hash = tmp[1127:872];
		meta.block_metadata.data_hash = tmp[871:616];
		meta.block_metadata.timestamp = tmp[615:584];
		meta.block_metadata.nonce = tmp[583:552];
		//meta.block_metadata.data = tmp[551:0];

		meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);

		//if(0 == curr_header_hash[255:255 - HEADER_HASH_ZERO_COUNT]){
		//	add_verify_success_count();
		//}else{
		//	add_verify_failed_count();
		//}

	}

	action write_block_to_list_according_index(bit<32> index, bit<32> count, bit<1128> content){
		block_list.write(index + (1024 * count), content);
	}

	action sync_block(){
		bit<32> index = 0;
		bit<32> b_index = 0;
		bit<1128> tmp = 0;
		bit<32> n_count = 0;
		bit<32> d_index = 0;

		done_index.read(d_index, 0);
		done_list.read(b_index, d_index);
		index = b_index % 1024;
		nodes_count.read(n_count, 0);

		block_list.read(tmp, b_index - 1);
		block_list.write(index + 0, tmp);
		block_list.write(index + (1024 * 1), tmp);
		block_list.write(index + (1024 * 2), tmp);
		block_list.write(index + (1024 * 3), tmp);
		block_list.write(index + (1024 * 4), tmp);
		block_list.write(index + (1024 * 5), tmp);
		block_list.write(index + (1024 * 6), tmp);
		block_list.write(index + (1024 * 7), tmp);
		block_list.write(index + (1024 * 8), tmp);
		block_list.write(index + (1024 * 9), tmp);
	}

	action copy_from_reg_to_reg_1(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		bit<1128> tmp = 0;
		block_list.read(tmp, (index_f * 1024) + start_index - 1);
		block_list.write((index_t * 1024) + start_index - 1, tmp);
		add_block_count((index_t * 1024) + start_index - 1, 1);
	}

	action copy_from_reg_to_reg_2(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_1(index_f, index_t, start_index);
		copy_from_reg_to_reg_1(index_f, index_t, start_index + 1);
	}

	action copy_from_reg_to_reg_4(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_2(index_f, index_t, start_index);
		copy_from_reg_to_reg_2(index_f, index_t, start_index + 2);
	}

	action copy_from_reg_to_reg_8(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_4(index_f, index_t, start_index);
		copy_from_reg_to_reg_4(index_f, index_t, start_index + 4);
	}

	action copy_from_reg_to_reg_16(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_8(index_f, index_t, start_index);
		copy_from_reg_to_reg_8(index_f, index_t, start_index + 8);
	}

	action copy_from_reg_to_reg_32(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_16(index_f, index_t, start_index);
		copy_from_reg_to_reg_16(index_f, index_t, start_index + 16);
	}

	action copy_from_reg_to_reg_64(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_32(index_f, index_t, start_index);
		copy_from_reg_to_reg_32(index_f, index_t, start_index + 32);
	}

	action copy_from_reg_to_reg_128(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_64(index_f, index_t, start_index);
		copy_from_reg_to_reg_64(index_f, index_t, start_index + 64);
	}

	action copy_from_reg_to_reg_256(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_128(index_f, index_t, start_index);
		copy_from_reg_to_reg_128(index_f, index_t, start_index + 128);
	}

	action copy_from_reg_to_reg_512(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_256(index_f, index_t, start_index);
		copy_from_reg_to_reg_256(index_f, index_t, start_index + 256);
	}

	action copy_from_reg_to_reg_1024(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_512(index_f, index_t, start_index);
		copy_from_reg_to_reg_512(index_f, index_t, start_index + 512);
	}

	action copy_from_reg_to_reg_2048(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		copy_from_reg_to_reg_1024(index_f, index_t, start_index);
		copy_from_reg_to_reg_1024(index_f, index_t, start_index + 1024);
	}

    apply {
		@atomic{
			// step 1: initialize the genesis block
			// step 2: analysis the request type
			// step 3: if the request type is init, init the env and create genesis block
			if((hdr.udp.request_type == INIT_REQUEST_L) || (hdr.udp.request_type == INIT_REQUEST_U)){
				if(standard_metadata.ingress_port == 1 && standard_metadata.egress_port == 0){
					multicast();
					init_nodes_count();
					init_block_count();
				}else{
					bit<32> n_count = 0;
					nodes_count.read(n_count, 0);
					if(standard_metadata.ingress_port > (((bit<9>)n_count * 2 + 1)) || standard_metadata.ingress_port % 2 == 0){
						change_egress_port();
						change_request_type();
						drop();
						return;
					}
					// set the block count to 0
					// create genesis block
					construct_genesis_block();
					read_block_from_list();
					// test
					hdr.udp.header_hash[8:0] = standard_metadata.ingress_port;
				}
				// broadcast, from port 1 to port 3 and 5, back to port 1
				change_egress_port();
			// step 4: if the request type is read, return the lastest block header hash to user
			}else if((hdr.udp.request_type == READ_REQUEST_L) || (hdr.udp.request_type == READ_REQUEST_U)){
				if(standard_metadata.ingress_port == 1){
					standard_metadata.egress_spec = 2;
					standard_metadata.egress_port = 2;
				}else if(standard_metadata.ingress_port == 3){
					hdr.ipv4.ttl = 53;
					read_block_from_list();
					standard_metadata.egress_spec = 1;
					standard_metadata.egress_port = 1;
				}
			// step 5: if the request type is write, create a new block and return the new block header hash to user
			}else if((hdr.udp.request_type == WRITE_REQUEST_L) || (hdr.udp.request_type == WRITE_REQUEST_U)){
				// step 5.1: broadcast write request to all nodes
				// step 5.2: all nodes start to do proof of work
				// step 5.3: one node broadcast its result to other nodes
				// step 5.4: other nodes stop to send out packet
				// step 5.5: save the result and send header hash to user

				if(standard_metadata.ingress_port == 1){
					init_proof_of_work_register();
					multicast();
				}else{
					// do proof of work job
					hdr.ipv4.ttl = 47;
					standard_metadata.egress_spec = 1;
					standard_metadata.egress_port = 1;
					bit<32> n_count = 0;
					nodes_count.read(n_count, 0);
					if(standard_metadata.ingress_port > (((bit<9>)n_count * 2 + 1)) || standard_metadata.ingress_port % 2 == 0){
						change_egress_port();
						change_request_type();
						drop();
						return;
					}
					bit<32> b_count = 0;
					get_node_seq_bl_bh_index();
					proof_of_work_done.read(b_count, 0);
					b_count = b_count & (32w1 << (bit<8>)meta.block_metadata.node_seq);

					if(b_count == 0){
						construct_new_block();
						if(0 != meta.block_metadata.curr_header_hash[255:255 - HEADER_HASH_ZERO_COUNT]){
							resubmit(standard_metadata);
						}else{
							hdr.ipv4.ttl = 51;
							set_proof_of_work_register();
							hdr.udp.header_hash[24:16] = standard_metadata.ingress_port;
							resubmit(standard_metadata);
						}
					}else{
						// 0. if verify_success_count is bigger than half of nodes count, drop;
						bit<32> vs_count = 0;
						bit<32> vf_count = 0;
						verify_success_count.read(vs_count, 0);
						verify_failed_count.read(vf_count, 0);
						nodes_count.read(n_count, 0);
						if(vs_count > (n_count >> 1) || vf_count > (n_count >> 1)){
							change_egress_port();
							change_request_type();
							drop();
							return;
						}
						// 1. read block from register done_list according done_index;
						// 2. verify this block;
						// 3. add verify_failed_count;
						verify_block();
						if(0 == meta.block_metadata.curr_header_hash[255:255 - HEADER_HASH_ZERO_COUNT]){
							add_verify_success_count();
						}else{
							add_verify_failed_count();
						}
						// 4. determine verify_success_count bigger than half of nodes_count
						//    4.1 if true, sync block and forward;
						//    4.2 if false, drop;
						verify_success_count.read(vs_count, 0);
						verify_failed_count.read(vf_count, 0);
						nodes_count.read(n_count, 0);
						if(vs_count > (n_count >> 1)){
							bit<32> index = 0;
							bit<32> b_index = 0;
							bit<1128> content = 0;
							bit<32> d_index = 0;

							done_index.read(d_index, 0);
							done_list.read(b_index, d_index);
							index = b_index % 1024;

							hdr.udp.header_hash[31:0] = n_count;
							hdr.udp.header_hash[16:8] = standard_metadata.ingress_port;
							hdr.udp.header_hash[47:16] = b_count;
							hdr.udp.header_hash[55:24] = b_count;
							hdr.udp.header_hash[63:32] = meta.block_metadata.node_seq;
							hdr.udp.header_hash[71:40] = vs_count;
							hdr.udp.header_hash[79:48] = vf_count;
							hdr.udp.header_hash[87:56] = index;
							hdr.udp.header_hash[95:64] = b_index;
							hdr.udp.header_hash[103:72] = d_index;

							block_list.read(content, b_index - 1);

							index = index - 1;
							write_block_to_list_according_index(index, 0, content);
							if(1 < n_count)
								write_block_to_list_according_index(index, 1, content);
							if(2 < n_count)
								write_block_to_list_according_index(index, 2, content);
							if(3 < n_count)
								write_block_to_list_according_index(index, 3, content);
							if(4 < n_count)
								write_block_to_list_according_index(index, 4, content);
							if(5 < n_count)
								write_block_to_list_according_index(index, 5, content);
							if(6 < n_count)
								write_block_to_list_according_index(index, 6, content);
							if(7 < n_count)
								write_block_to_list_according_index(index, 7, content);
							if(8 < n_count)
								write_block_to_list_according_index(index, 8, content);
							if(9 < n_count)
								write_block_to_list_according_index(index, 9, content);

							//hdr.udp.header_hash = content[1127:872];
							hdr.ipv4.ttl = 41;
							//hdr.udp.header_hash[24:16] = standard_metadata.ingress_port;
							standard_metadata.egress_spec = 1;
							standard_metadata.egress_port = 1;
						}else if(vf_count > (n_count >> 1)){
							add_done_index();
							standard_metadata.egress_spec = 1;
							standard_metadata.egress_port = 1;
						}else{
							change_egress_port();
							change_request_type();
							drop();
						}
					}
				}
			}else if((hdr.udp.request_type == JOIN_REQUEST_L) || (hdr.udp.request_type == JOIN_REQUEST_U)){
				if(standard_metadata.ingress_port == 1){
					multicast();
					add_nodes_count();
				}else{
					bit<32> n_count = 0;
					nodes_count.read(n_count, 0);
					if(standard_metadata.ingress_port > (((bit<9>)n_count * 2 + 1)) || standard_metadata.ingress_port % 2 == 0){
						change_egress_port();
						change_request_type();
						drop();
					}else{
						// sync_func
						// step 1: get the max block count node's index
						bit<32> max_block_count = 0;
						bit<32> max_block_index = 0;
						bit<32> tmp_count = 0;
						block_count.read(tmp_count, 0);
						max_block_count = tmp_count;
						max_block_index = 0;
						if(1 < n_count){
							block_count.read(tmp_count, 1);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 1;
							}
						}else if(2 < n_count){
							block_count.read(tmp_count, 2);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 2;
							}
						}else if(3 < n_count){
							block_count.read(tmp_count, 3);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 3;
							}
						}else if(4 < n_count){
							block_count.read(tmp_count, 4);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 4;
							}
						}else if(5 < n_count){
							block_count.read(tmp_count, 5);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 5;
							}
						}else if(6 < n_count){
							block_count.read(tmp_count, 6);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 6;
							}
						}else if(7 < n_count){
							block_count.read(tmp_count, 7);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 7;
							}
						}else if(8 < n_count){
							block_count.read(tmp_count, 8);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 8;
							}
						}else if(9 < n_count){
							block_count.read(tmp_count, 9);
							if(tmp_count > max_block_count){
								max_block_count = tmp_count;
								max_block_index = 9;
							}
						}
						// step 2: sync block from max node index
						bit<32> curr_node_index = n_count - 1;
						if(max_block_count & 0x0001 != 0){
							copy_from_reg_to_reg_1(max_block_index, curr_node_index, 1);
						}
						if(max_block_count & 0x0002 != 0){
							copy_from_reg_to_reg_2(max_block_index, curr_node_index, 2);
						}
						if(max_block_count & 0x0004 != 0){
							copy_from_reg_to_reg_4(max_block_index, curr_node_index, 4);
						}
						if(max_block_count & 0x0008 != 0){
							copy_from_reg_to_reg_8(max_block_index, curr_node_index, 8);
						}
						if(max_block_count & 0x0010 != 0){
							copy_from_reg_to_reg_16(max_block_index, curr_node_index, 16);
						}
						if(max_block_count & 0x0020 != 0){
							copy_from_reg_to_reg_32(max_block_index, curr_node_index, 32);
						}
						if(max_block_count & 0x0040 != 0){
							copy_from_reg_to_reg_64(max_block_index, curr_node_index, 64);
						}
						if(max_block_count & 0x0080 != 0){
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 128);
						}
						if(max_block_count & 0x0100 != 0){
							copy_from_reg_to_reg_256(max_block_index, curr_node_index, 256);
						}
						if(max_block_count & 0x0200 != 0){
							copy_from_reg_to_reg_512(max_block_index, curr_node_index, 512);
						}
						if(max_block_count & 0x0400 != 0){
							copy_from_reg_to_reg_1024(max_block_index, curr_node_index, 1024);
						}
						// step 3: return block count
						hdr.udp.header_hash[31:0] = n_count;
						hdr.udp.header_hash[16:8] = standard_metadata.ingress_port;
						hdr.udp.header_hash[47:16] = max_block_count;
						hdr.udp.header_hash[55:24] = max_block_index;
						standard_metadata.egress_spec = 1;
						standard_metadata.egress_port = 1;
						hdr.ipv4.ttl = 47;
					}
				}
			}else if((hdr.udp.request_type == EXIT_REQUEST_L) || (hdr.udp.request_type == EXIT_REQUEST_U)){
				//drop();
				polling_packet();
			}else{
				drop();
			}
			// step 6: if the request type is sync, do sync job
		}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

	action drop() {
	    mark_to_drop(standard_metadata);
	}

	action change_request_type() {
		bit<8> tmp;
		tmp = hdr.udp.request_type;
		tmp = tmp + 0;
		hdr.udp.request_type = tmp;
	}

    apply { 
		//if (standard_metadata.egress_port == 1 && standard_metadata.ingress_port == 1)
		//	change_request_type();
		//else if(standard_metadata.ingress_port == standard_metadata.egress_port)
		//	drop();
		//else if(standard_metadata.egress_port == 1 && standard_metadata.ingress_port != 1)
		//	drop();
		
		if(standard_metadata.ingress_port == standard_metadata.egress_port){
			drop();
		}
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
			  hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
	update_checksum_with_payload(
	        hdr.udp.isValid(),
	        {
	        hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, hdr.ipv4.totalLen, 16w0xffeb,
	        hdr.udp.sport,
	        hdr.udp.dport,
	        hdr.udp.length,
	        hdr.udp.request_type,
	        hdr.udp.header_hash,
	        hdr.udp.data
	        },
	        hdr.udp.checksum,
	        HashAlgorithm.csum16);
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
