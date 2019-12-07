/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<552>  data_string = 0x5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


// 'r','w','s' 
#define READ_REQUEST_L  0x72
#define READ_REQUEST_U  0x52
#define WRITE_REQUEST_L 0x77
#define WRITE_REQUEST_U 0x57
#define SYNC_REQUEST_L  0x73
#define SYNC_REQUEST_U  0x53

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
	bit<256>  pre_header_hash;
	bit<256>  data_hash;
	bit<32>   timestamp;
	bit<32>   nonce;
	bit<552>  data;
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

//register<bit<1>>(1) re_count;

register<bit<1128>>(1024)  block_list;
register<bit<32>>(1)       block_count;


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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

	action add_block_count(){
		bit<32> count = 0;
		block_count.read(count, 0);
		count = count + 1;
		block_count.write(0, count);
	}

	action minus_block_count(){
		bit<32> count = 0;
		block_count.read(count, 0);
		count = count - 1;
		block_count.write(0, count);
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
		bit<32> index = 0;
		block_count.read(index, 0);
		block_list.write(index, tmp);
		add_block_count();
	}

	action read_block_from_list(){
		bit<1128> tmp = 0;
		bit<32> index = 0;
		
		block_count.read(index, 0);
		block_list.read(tmp, index);
	}

	action construct_genesis_block(){
		meta.block_metadata.pre_header_hash = 65535;
		meta.block_metadata.data_hash = 255;
		get_timestamp();
		get_random();
		meta.block_metadata.data = hdr.udp.data;
		add_block_to_list();
	}

    apply {

		// broadcast
		if(standard_metadata.ingress_port == 1){
			multicast();
		//}else if(standard_metadata.ingress_port == 5){
		//	change_request_type();
		}
		change_egress_port();

		if(hdr.udp.request_type == READ_REQUEST_L){
			construct_genesis_block();
			hdr.udp.header_hash = meta.block_metadata.pre_header_hash;
		}else{
			hdr.udp.header_hash = 255;
		}

		//change_request_type();
		//get_timestamp();
		//get_random();
		//add_block_to_list();
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
		tmp = tmp + 1;
		hdr.udp.request_type = tmp;
	}

    apply { 
		if (standard_metadata.egress_port == 1 && standard_metadata.ingress_port == 1)
			change_request_type();
		else if(standard_metadata.ingress_port == standard_metadata.egress_port)
			drop();
		//else if(standard_metadata.egress_port == 1 && standard_metadata.ingress_port != 1)
		//	drop();
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
