/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


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
    bit<8>  payload;
}


struct block_metadata_t {
	bit<256>  pre_header_hash;
	bit<256>  data_hash;
	bit<32>   timestamp;
	bit<32>   nonce;
	bit<8>  data;
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
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

	action polling_packet(){
		if(standard_metadata.ingress_port == 1){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 1;
			standard_metadata.egress_port = 2;
			standard_metadata.egress_spec = 2;
		}else if(standard_metadata.ingress_port == 2){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 2;
		}else if(standard_metadata.ingress_port == 3){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 3;
			standard_metadata.egress_port = 4;
			standard_metadata.egress_spec = 4;
		}else if(standard_metadata.ingress_port == 4){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 4;
		}else if(standard_metadata.ingress_port == 5){
			hdr.ipv4.ttl = hdr.ipv4.ttl  - 5;
			standard_metadata.egress_port = 1;
			standard_metadata.egress_spec = 1;
		}

	}

	action read_request_from_user(){
	}

	action write_request_from_user(){
	}

	action sync_request_from_new_node(){
	}

	action change_payload() {
		bit<8> tmp;
		tmp = hdr.udp.payload;
		tmp = tmp + 1;
		hdr.udp.payload = tmp;
	}

	action get_request_type(){
		if (hdr.udp.payload == READ_REQUEST_L || hdr.udp.payload == READ_REQUEST_U){
			hdr.udp.payload = WRITE_REQUEST_U;
		}
	}

    apply {
		polling_packet();
		//change_payload();
		get_request_type();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
	        hdr.udp.payload
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
