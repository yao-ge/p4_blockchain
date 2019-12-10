/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<552>  data_string = 0x5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


// 'i', 'r','w','s' 
#define INIT_REQUEST_L  0x69
#define INIT_REQUEST_U  0x49
#define READ_REQUEST_L  0x72
#define READ_REQUEST_U  0x52
#define WRITE_REQUEST_L 0x77
#define WRITE_REQUEST_U 0x57
#define SYNC_REQUEST_L  0x73
#define SYNC_REQUEST_U  0x53

#define HEADER_HASH_ZERO_COUNT 4

#define SINGLE_NODE_BLOCK_COUNT 1024
#define NODE_SEQ(in_port) in_port/2    // max = 9, begin from 0
#define BLOCK_LIST_INDEX(node_seq, b_count) (node_seq * SINGLE_NODE_BLOCK_COUNT) + b_count    // max = 10240
#define BLOCK_HEADER_HASH_LIST_INDEX(node_seq, b_count) (node_seq * SINGLE_NODE_BLOCK_COUNT) + b_count    // max = 10240

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
register<bit<1128>>(10240)  block_list;                      // save block 
register<bit<256>>(10240)   curr_block_header_hash_list;     // save header hash of block
register<bit<32>>(10)       block_count;					 // indicate block count of each node
register<bit<32>>(10)       done_list;						 // record the node who has finished proof of work
register<bit<32>>(1)		proof_of_work_done;				 // indicate node has finish proof of work
register<bit<32>>(1)        done_count;						 // count of node done proof of work
register<bit<32>>(1)		done_index;						 // index of done register, begin from zero. for verify
register<bit<32>>(1)        verify_sha256_nodes_count;       // finish verify nodes count
register<bit<32>>(1)        nodes_count;                     // total nodes count
register<bit<1>>(1)			verify_finish;					 // indicate verify action is finished


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
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}else if(standard_metadata.ingress_port == 7){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 7;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}
	}

	action change_request_type() {
		bit<8> tmp;
		tmp = hdr.udp.request_type;
		tmp = tmp + 1;
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
		}else if(hdr.udp.request_type == SYNC_REQUEST_L){
			hdr.udp.request_type = SYNC_REQUEST_U;
		}else if(hdr.udp.request_type == SYNC_REQUEST_U){
			hdr.udp.request_type = SYNC_REQUEST_L;
		}
	}

	action get_node_seq_bl_bh_index(){
		bit<32> b_count = 0;

		meta.block_metadata.node_seq[8:0] = NODE_SEQ(standard_metadata.ingress_port);
		block_count.read(b_count, meta.block_metadata.node_seq);
		meta.block_metadata.bl_index = BLOCK_LIST_INDEX(meta.block_metadata.node_seq, b_count);
		meta.block_metadata.bh_index = BLOCK_HEADER_HASH_LIST_INDEX(meta.block_metadata.node_seq, b_count);
	}

	action set_block_count_to_zero(){
		bit<32> count = 0;

		get_node_seq_bl_bh_index();
		block_count.write(meta.block_metadata.node_seq, 0);
	}

	action add_block_count(){
		bit<32> count = 0;

		get_node_seq_bl_bh_index();
		block_count.read(count, meta.block_metadata.node_seq);
		count = count + 1;
		block_count.write(meta.block_metadata.node_seq, count);
	}

	action minus_block_count(){
		bit<32> count = 0;

		get_node_seq_bl_bh_index();
		block_count.read(count, meta.block_metadata.node_seq);
		count = count - 1;
		block_count.write(meta.block_metadata.node_seq, count);
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
		add_block_count();
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
		//get_timestamp();
		//get_random();
		meta.block_metadata.timestamp = 0;
		meta.block_metadata.nonce = 0;
		meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+\
				meta.block_metadata.data_hash+meta.block_metadata.timestamp+\
				meta.block_metadata.nonce);
		add_block_to_list();
	}

	action construct_new_block() {
		meta.block_metadata.pre_header_hash = meta.block_metadata.curr_header_hash;
		meta.block_metadata.data = data_string;
		meta.block_metadata.data_hash = FAKE_SHA256(meta.block_metadata.data);
		get_timestamp();
		get_random();
		meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+\
				meta.block_metadata.data_hash+meta.block_metadata.timestamp+\
				meta.block_metadata.nonce);
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
		verify_sha256_nodes_count.write(0, 0);
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
		nodes_count.write(0, 0);
	}

	action add_nodes_count(){
		bit<32> tmp = 0;
		nodes_count.read(tmp, 0);
		tmp = tmp + 1;
		nodes_count.write(0, tmp);
	}

	action init_verify_nodes_count(){
		verify_sha256_nodes_count.write(0, 0);
	}

	action add_verify_nodes_count(){
		bit<32> tmp = 0;
		verify_sha256_nodes_count.read(tmp, 0);
		tmp = tmp + 1;
		verify_sha256_nodes_count.write(0, tmp);
	}

	action verify_block(){
		bit<1128> tmp = 0;
		bit<256>  curr_header_hash = 0;
		bit<32>   bl_count = 0;

		get_node_seq_bl_bh_index();
		done_list.read(bl_count, 0);

		block_list.read(tmp, bl_count);

		meta.block_metadata.pre_header_hash = tmp[1127:872];
		meta.block_metadata.data_hash = tmp[871:616];
		meta.block_metadata.timestamp = tmp[615:584];
		meta.block_metadata.nonce = tmp[583:552];
		//meta.block_metadata.data = tmp[551:0];

		curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+\
				meta.block_metadata.data_hash+meta.block_metadata.timestamp+\
				meta.block_metadata.nonce);

		if(0 == curr_header_hash[255:255 - HEADER_HASH_ZERO_COUNT]){
			add_verify_nodes_count();
		}
	}


    apply {
		@atomic{
			// step 1: initialize the genesis block
			// step 2: analysis the request type
			// step 3: if the request type is init, init the env and create genesis block
			if((hdr.udp.request_type == INIT_REQUEST_L) || (hdr.udp.request_type == INIT_REQUEST_U)){
				if(standard_metadata.ingress_port == 1){
					multicast();
					init_nodes_count();
				}else{
					// set the block count to 0
					set_block_count_to_zero();
					// create genesis block
					construct_genesis_block();
					read_block_from_list();
					add_nodes_count();
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
					bit<32> b_count = 0;
					get_node_seq_bl_bh_index();
					proof_of_work_done.read(b_count, 0);
					b_count = b_count & (32w1 << (bit<8>)meta.block_metadata.node_seq);
					if(b_count == 0){
						construct_new_block();
						if(0 != meta.block_metadata.curr_header_hash[255:255 - HEADER_HASH_ZERO_COUNT]){
							resubmit(standard_metadata);
							return;
						}else{
							hdr.ipv4.ttl = 51;
							set_proof_of_work_register();
							hdr.udp.header_hash[24:16] = standard_metadata.ingress_port;
							resubmit(standard_metadata);
						}
					}else{
						read_block_from_list();
						hdr.udp.header_hash[16:8] = standard_metadata.ingress_port;
						hdr.ipv4.ttl = 53;
						standard_metadata.egress_spec = 1;
						standard_metadata.egress_port = 1;
						//drop();
					}
				}
			}else{
				polling_packet();
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
