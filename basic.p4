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

#define PRE_HEADER_STR  0X00
#define CURR_HEADER_STR	0x01
#define DATA_STR		0x02
#define TEST_STR		0X03

#define SHA256_SECTION 1

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
	bit<8>    nodes_count;
	bit<32>   block_count;
	bit<256>  pre_header_hash;
	bit<256>  curr_header_hash;
	bit<256>  data_hash;
	bit<32>   timestamp;
	bit<32>   nonce;
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
#if SHA256_SECTION
    bit<64> len;
    bit<64> length;
    bit<64> all_len;
    bit<32> mask;
    bit<32> pad;
    bit<32> a;
    bit<32> b;
    bit<32> c;
    bit<32> d;
    bit<32> e;
    bit<32> f;
    bit<32> g;
    bit<32> h;
    bit<32> h0;
    bit<32> h1;
    bit<32> h2;
    bit<32> h3;
    bit<32> h4;
    bit<32> h5;
    bit<32> h6;
    bit<32> h7;
    bit<32> s0;
    bit<32> s1;
    bit<32> t1;
    bit<32> t2;
    bit<32> maj;
    bit<32> ch;

    bit<32> w0;
    bit<32> w1;
    bit<32> w2;
    bit<32> w3;
    bit<32> w4;
    bit<32> w5;
    bit<32> w6;
    bit<32> w7;
    bit<32> w8;
    bit<32> w9;
    bit<32> w10;
    bit<32> w11;
    bit<32> w12;
    bit<32> w13;
    bit<32> w14;
    bit<32> w15;
    bit<32> w16;
    bit<32> w17;
    bit<32> w18;
    bit<32> w19;
    bit<32> w20;
    bit<32> w21;
    bit<32> w22;
    bit<32> w23;
    bit<32> w24;
    bit<32> w25;
    bit<32> w26;
    bit<32> w27;
    bit<32> w28;
    bit<32> w29;
    bit<32> w30;
    bit<32> w31;
    bit<32> w32;
    bit<32> w33;
    bit<32> w34;
    bit<32> w35;
    bit<32> w36;
    bit<32> w37;
    bit<32> w38;
    bit<32> w39;
    bit<32> w40;
    bit<32> w41;
    bit<32> w42;
    bit<32> w43;
    bit<32> w44;
    bit<32> w45;
    bit<32> w46;
    bit<32> w47;
    bit<32> w48;
    bit<32> w49;
    bit<32> w50;
    bit<32> w51;
    bit<32> w52;
    bit<32> w53;
    bit<32> w54;
    bit<32> w55;
    bit<32> w56;
    bit<32> w57;
    bit<32> w58;
    bit<32> w59;
    bit<32> w60;
    bit<32> w61;
    bit<32> w62;
    bit<32> w63;

    bit<16>   count; 
    bit<16>   max_count; 
    bit<32>   data;
#endif
}

#if SHA256_SECTION
struct S{
    bit<32> k0;
    bit<32> k1;
    bit<32> k2;
    bit<32> k3;
    bit<32> k4;
    bit<32> k5;
    bit<32> k6;
    bit<32> k7;
    bit<32> k8;
    bit<32> k9;
    bit<32> k10;
    bit<32> k11;
    bit<32> k12;
    bit<32> k13;
    bit<32> k14;
    bit<32> k15;
    bit<32> k16;
    bit<32> k17;
    bit<32> k18;
    bit<32> k19;
    bit<32> k20;
    bit<32> k21;
    bit<32> k22;
    bit<32> k23;
    bit<32> k24;
    bit<32> k25;
    bit<32> k26;
    bit<32> k27;
    bit<32> k28;
    bit<32> k29;
    bit<32> k30;
    bit<32> k31;
    bit<32> k32;
    bit<32> k33;
    bit<32> k34;
    bit<32> k35;
    bit<32> k36;
    bit<32> k37;
    bit<32> k38;
    bit<32> k39;
    bit<32> k40;
    bit<32> k41;
    bit<32> k42;
    bit<32> k43;
    bit<32> k44;
    bit<32> k45;
    bit<32> k46;
    bit<32> k47;
    bit<32> k48;
    bit<32> k49;
    bit<32> k50;
    bit<32> k51;
    bit<32> k52;
    bit<32> k53;
    bit<32> k54;
    bit<32> k55;
    bit<32> k56;
    bit<32> k57;
    bit<32> k58;
    bit<32> k59;
    bit<32> k60;
    bit<32> k61;
    bit<32> k62;
    bit<32> k63;
}

const S K =  {
     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define RL(x,n) (((x) << n) | ((x) >> (32-n)))
#define RR(x,n) (((x) >> n) | ((x) << (32-n)))

#define S0(x)  (RR((x), 2) ^ RR((x),13) ^ RR((x),22))
#define S1(x)  (RR((x), 6) ^ RR((x),11) ^ RR((x),25))
#define G0(x)  (RR((x), 7) ^ RR((x),18) ^ ((x) >> 3))
#define G1(x)  (RR((x),17) ^ RR((x),19) ^ ((x) >> 10))
#endif

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
register<bit<32>>(1)									  verify_index;					   // index of done register, begin from zero. for verify
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


#if SHA256_SECTION
#define extend(i,j,k,l,m) meta.w##k = meta.w##l + G0(meta.w##i) + meta.w##m + G1(meta.w##j)
#define main_operation(i)   meta.maj = (meta.a & meta.b) ^ (meta.a & meta.c) ^ (meta.b & meta.c); \
                            meta.t2 = S0(meta.a) + meta.maj; \
                            meta.ch = (meta.e & meta.f) ^ ((~meta.e)& meta.g ); \
                            meta.t1 = meta.h + S1(meta.e) + meta.ch + K.k##i + meta.w##i; \
                            meta.h = meta.g; \
                            meta.g = meta.f; \
                            meta.f = meta.e; \
                            meta.e = meta.d + meta.t1; \
                            meta.d = meta.c; \
                            meta.c = meta.b; \
                            meta.b = meta.a; \
                            meta.a = meta.t1 + meta.t2;

    action sha256_load(bit<32> control_lable, bit<32> str_type){

        bit<256> m0 = 0;
        bit<256> m1 = 0;

        if( (meta.pad == 0) && (meta.len > 0) ) {
			if(control_lable == 0){
				if(str_type == DATA_STR){
					m0 = meta.block_metadata.data[551:296];
					m1 = meta.block_metadata.data[295:40];
				}else if(str_type == PRE_HEADER_STR || str_type == CURR_HEADER_STR){
					m0 = meta.block_metadata.pre_header_hash;
					m1 = meta.block_metadata.data_hash;
				}else if(str_type == TEST_STR){
					m0 = data_string[551:296];
					m1 = data_string[295:40];
				}
			}else if(control_lable == 1){
				if(str_type == DATA_STR){
					m0[255:216] = meta.block_metadata.data[39:0];
				}else if(str_type == PRE_HEADER_STR || str_type == CURR_HEADER_STR){
					m0[255:224] = meta.block_metadata.timestamp;
					m0[223:192] = meta.block_metadata.nonce;
				}else if(str_type == TEST_STR){
					m0[255:216] = data_string[39:0];
					m1 = 0;
					hdr.udp.data[511:256] = data_string[551:296];
					hdr.udp.data[255:0] = data_string[295:40];
				}
			}
        }


        meta.w0 = m0[255:224];
        meta.w1 = m0[223:192];
        meta.w2 = m0[191:160];
        meta.w3 = m0[159:128];
        meta.w4 = m0[127:96];
        meta.w5 = m0[95:64];
        meta.w6 = m0[63:32];
        meta.w7 = m0[31:0];
        meta.w8 = m1[255:224];
        meta.w9 = m1[223:192];
        meta.w10 = m1[191:160];
        meta.w11 = m1[159:128];
        meta.w12 = m1[127:96];
        meta.w13 = m1[95:64];
        meta.w14 = m1[63:32];
        meta.w15 = m1[31:0];
    }

    action sha256_cal_mask(){
        if((meta.len % 4) == 0) meta.mask = 0x80000000;
        if((meta.len % 4) == 1) meta.mask = 0x00800000;
        if((meta.len % 4) == 2) meta.mask = 0x00008000;
        if((meta.len % 4) == 3) meta.mask = 0x00000080;
    }
    
    action sha256_padding(){
        //add padding
        if(meta.len >= 64){
            meta.len = meta.len - 64;
            meta.length = 64;
            return;
        }
        if(meta.len >= 56 ){
            meta.len = meta.len - 56;
            meta.length = 56;
            sha256_cal_mask();
            meta.len = meta.len >> 2;
            if(meta.len == 0)meta.w14 = meta.w14 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w15 = meta.w15 | meta.mask;
            meta.len = meta.len - 1;
            meta.len = meta.len << 2;
            meta.len = 0;
            meta.pad = 1;
            return;
        }
        
        if( meta.pad == 0) {
            sha256_cal_mask();
            meta.len = meta.len >> 2;
            if(meta.len == 0)meta.w0 = meta.w0 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w1 = meta.w1 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w2 = meta.w2 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w3 = meta.w3 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w4 = meta.w4 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w5 = meta.w5 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w6 = meta.w6 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w7 = meta.w7 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w8 = meta.w8 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w9 = meta.w9 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w10 = meta.w10 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w11 = meta.w11 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w12 = meta.w12 | meta.mask;
            meta.len = meta.len - 1;
            if(meta.len == 0)meta.w13 = meta.w13 | meta.mask;
            meta.length = meta.len;
            meta.len = 0;
            meta.pad = 1;
        }

        // add length
        //meta.w14 = (bit<32>)(hdr.length.len >> 29);
        //meta.w15 = (bit<32>)(hdr.length.len << 3);
        meta.w14 = (bit<32>)(meta.all_len >> 29);
        meta.w15 = (bit<32>)(meta.all_len << 3);
    }


    action sha256_extend1(){
        extend(1,14,16,0,9);
        extend(2,15,17,1,10);
        extend(3,16,18,2,11);
        extend(4,17,19,3,12);
        extend(5,18,20,4,13);
        extend(6,19,21,5,14);
        extend(7,20,22,6,15);
        extend(8,21,23,7,16);
    }  
    action sha256_extend2(){
        extend(9,22,24,8,17);
        extend(10,23,25,9,18);
        extend(11,24,26,10,19);
        extend(12,25,27,11,20);
        extend(13,26,28,12,21);
        extend(14,27,29,13,22);
        extend(15,28,30,14,23);
        extend(16,29,31,15,24);
    }  
    action sha256_extend3(){
        extend(17,30,32,16,25);
        extend(18,31,33,17,26);
        extend(19,32,34,18,27);
        extend(20,33,35,19,28);
        extend(21,34,36,20,29);
        extend(22,35,37,21,30);
        extend(23,36,38,22,31);
        extend(24,37,39,23,32);
    }  
    action sha256_extend4(){
        extend(25,38,40,24,33);
        extend(26,39,41,25,34);
        extend(27,40,42,26,35);
        extend(28,41,43,27,36);
        extend(29,42,44,28,37);
        extend(30,43,45,29,38);
        extend(31,44,46,30,39);
        extend(32,45,47,31,40);
    }  
    action sha256_extend5(){
        extend(33,46,48,32,41);
        extend(34,47,49,33,42);
        extend(35,48,50,34,43);
        extend(36,49,51,35,44);
        extend(37,50,52,36,45);
        extend(38,51,53,37,46);
        extend(39,52,54,38,47);
        extend(40,53,55,39,48);
    }  
    action sha256_extend6(){
        extend(41,54,56,40,49);
        extend(42,55,57,41,50);
        extend(43,56,58,42,51);
        extend(44,57,59,43,52);
        extend(45,58,60,44,53);
        extend(46,59,61,45,54);
        extend(47,60,62,46,55);
        extend(48,61,63,47,56);
    }

    action sha256_extend()
    {
        sha256_extend1();
        sha256_extend2();
        sha256_extend3();
        sha256_extend4();
        sha256_extend5();
        sha256_extend6();
    }
 
    action sha256_first(){
        meta.h0 = 0x6a09e667; 
        meta.h1 = 0xbb67ae85;
        meta.h2 = 0x3c6ef372; 
        meta.h3 = 0xa54ff53a;
        meta.h4 = 0x510e527f;
        meta.h5 = 0x9b05688c;
        meta.h6 = 0x1f83d9ab;
        meta.h7 = 0x5be0cd19;
    }


    action sha256_init(){
        meta.a = meta.h0;
        meta.b = meta.h1;
        meta.c = meta.h2;
        meta.d = meta.h3;
        meta.e = meta.h4;
        meta.f = meta.h5;
        meta.g = meta.h6;
        meta.h = meta.h7;
    }

    action sha256_main1(){
        main_operation(0);
        main_operation(1);
        main_operation(2);
        main_operation(3);
        main_operation(4);
        main_operation(5);
        main_operation(6);
        main_operation(7);
    }
    action sha256_main2(){
        main_operation(8);
        main_operation(9);
        main_operation(10);
        main_operation(11);
        main_operation(12);
        main_operation(13);
        main_operation(14);
        main_operation(15);
    }
    action sha256_main3(){
        main_operation(16);
        main_operation(17);
        main_operation(18);
        main_operation(19);
        main_operation(20);
        main_operation(21);
        main_operation(22);
        main_operation(23);
    }
    action sha256_main4(){
        main_operation(24);
        main_operation(25);
        main_operation(26);
        main_operation(27);
        main_operation(28);
        main_operation(29);
        main_operation(30);
        main_operation(31);
    }
    action sha256_main5(){
        main_operation(32);
        main_operation(33);
        main_operation(34);
        main_operation(35);
        main_operation(36);
        main_operation(37);
        main_operation(38);
        main_operation(39);
    }
    action sha256_main6(){
        main_operation(40);
        main_operation(41);
        main_operation(42);
        main_operation(43);
        main_operation(44);
        main_operation(45);
        main_operation(46);
        main_operation(47);
    }
    action sha256_main7(){
        main_operation(48);
        main_operation(49);
        main_operation(50);
        main_operation(51);
        main_operation(52);
        main_operation(53);
        main_operation(54);
        main_operation(55);
    }
    action sha256_main8(){
        main_operation(56);
        main_operation(57);
        main_operation(58);
        main_operation(59);
        main_operation(60);
        main_operation(61);
        main_operation(62);
        main_operation(63);
    }

    action sha256_main()
    {
        sha256_main1();
        sha256_main2();
        sha256_main3();
        sha256_main4();
        sha256_main5();
        sha256_main6();
        sha256_main7();
        sha256_main8();
    }

    action sha256_end(){
        meta.h0 = meta.h0 + meta.a;
        meta.h1 = meta.h1 + meta.b;
        meta.h2 = meta.h2 + meta.c;
        meta.h3 = meta.h3 + meta.d;
        meta.h4 = meta.h4 + meta.e;
        meta.h5 = meta.h5 + meta.f;
        meta.h6 = meta.h6 + meta.g;
        meta.h7 = meta.h7 + meta.h;
    }

#define REAL_SHA256(i, j)   sha256_load(i, j);\
							sha256_padding(); \
							sha256_extend1(); \
							sha256_extend2(); \
							sha256_extend3(); \
							sha256_extend4(); \
							sha256_extend5(); \
							sha256_extend6(); \
							sha256_init(); \
							sha256_main1(); \
							sha256_main2(); \
							sha256_main3(); \
							sha256_main4(); \
							sha256_main5(); \
							sha256_main6(); \
							sha256_main7(); \
							sha256_main8(); \
							sha256_end();


    action forward() {
        /* TODO: fill out code in action body */
		standard_metadata.egress_spec = 1;
    } 

	action get_sha256(bit<64> str_len, bit<32> str_type){
		bit<256> tmp = 0;
		meta.all_len = str_len;
		meta.len = str_len;
		meta.pad = 0;
		meta.max_count = (bit<16>)(meta.len >> 6) + 1;
		if(((meta.len % 64) >= 56)){
			meta.max_count = meta.max_count + 1;
		}
		sha256_first();

		if(0 < meta.max_count){
			REAL_SHA256(0, str_type);
		}

		if(1 < meta.max_count){
			REAL_SHA256(1, str_type);
		}

		tmp[255:224] = meta.h0;
		tmp[223:192] = meta.h1;
		tmp[191:160] = meta.h2;
		tmp[159:128] = meta.h3;
		tmp[127:96] = meta.h4;
		tmp[95:64] = meta.h5;
		tmp[63:32] = meta.h6;
		tmp[31:0] = meta.h7;

		if(str_type == PRE_HEADER_STR){
			meta.block_metadata.pre_header_hash = tmp;
		}else if(str_type == CURR_HEADER_STR){
			meta.block_metadata.curr_header_hash = tmp;
		}else if(str_type == DATA_STR){
			meta.block_metadata.data_hash = tmp;
		}
		
	}

#endif

	action forward_to_dest_port(bit<9> dst_port){
		standard_metadata.egress_port = dst_port;
		standard_metadata.egress_spec = dst_port;
	}

	action change_egress_port(){
		hdr.ipv4.ttl = hdr.ipv4.ttl - (bit<8>)standard_metadata.ingress_port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		forward_to_dest_port(1);
	}

	action polling_packet(){
		hdr.ipv4.ttl = hdr.ipv4.ttl - (bit<8>)standard_metadata.ingress_port;
		if(standard_metadata.ingress_port == 7){
			forward_to_dest_port(1);
		}else{
			forward_to_dest_port(standard_metadata.ingress_port + 1);
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

	action get_node_seq_bl_bh_index(){
		bit<32> b_count = 0;

		meta.block_metadata.node_seq[8:0] = NODE_SEQ(standard_metadata.ingress_port);
		block_count.read(b_count, meta.block_metadata.node_seq);
		meta.block_metadata.bl_index = BLOCK_LIST_INDEX(meta.block_metadata.node_seq, b_count);
		meta.block_metadata.bh_index = BLOCK_HEADER_HASH_LIST_INDEX(meta.block_metadata.node_seq, b_count);
	}

	action init_block_count(){
		bit<32> count = 0;

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
	}

	action read_header_hash_from_list(){
		bit<256> tmp = 0;

		get_node_seq_bl_bh_index();
		curr_block_header_hash_list.read(tmp, meta.block_metadata.bh_index - 1);
		meta.block_metadata.curr_header_hash = tmp;
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
		meta.block_metadata.pre_header_hash = 0;
		meta.block_metadata.data = data_string;
		//meta.block_metadata.data_hash = FAKE_SHA256(meta.block_metadata.data);
		get_sha256(69, DATA_STR);
		meta.block_metadata.timestamp = 0;
		meta.block_metadata.nonce = 0;
		//meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		get_sha256(72, CURR_HEADER_STR);
		add_block_to_list();
	}

	action construct_new_block() {
		read_block_from_list();
		//meta.block_metadata.pre_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		get_sha256(72, PRE_HEADER_STR);
		meta.block_metadata.data = data_string;
		//meta.block_metadata.data_hash = FAKE_SHA256(meta.block_metadata.data);
		get_sha256(69, DATA_STR);
		get_timestamp();
		get_random();
		//meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		get_sha256(72, CURR_HEADER_STR);
		//add_block_to_list();
	}

	action add_verify_index(){
		bit<32> tmp = 0;
		verify_index.read(tmp, 0);
		tmp = tmp + 1;
		verify_index.write(0, tmp);
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
		verify_index.write(0, 0);
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

		verify_index.read(d_index, 0);

		done_list.read(bl_count, d_index);

		block_list.read(tmp, bl_count - 1);

		meta.block_metadata.pre_header_hash = tmp[1127:872];
		meta.block_metadata.data_hash = tmp[871:616];
		meta.block_metadata.timestamp = tmp[615:584];
		meta.block_metadata.nonce = tmp[583:552];
		//meta.block_metadata.data = tmp[551:0];

		get_sha256(72, CURR_HEADER_STR);

		//if(d_index == 0){
		//	meta.block_metadata.curr_header_hash = 0x111111111111111111111111111111111111111111111111111111111111111F;
		//}else{
		//	meta.block_metadata.curr_header_hash = FAKE_SHA256(meta.block_metadata.pre_header_hash+meta.block_metadata.data_hash+meta.block_metadata.timestamp+meta.block_metadata.nonce);
		//}
	}

	action write_block_to_list_according_index(bit<32> index, bit<32> count, bit<1128> content){
		block_list.write(index + (1024 * count), content);
	}

	action copy_from_reg_to_reg_1(bit<32> index_f, bit<32> index_t, bit<32> start_index){
		bit<1128> tmp = 0;
		block_list.read(tmp, (index_f * 1024) + start_index - 1);
		block_list.write((index_t * 1024) + start_index - 1, tmp);
		add_block_count(index_t, 1);
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

	action output_to_hdr(){
		bit<32> count = 0;
		nodes_count.read(count, 0);
		hdr.udp.nodes_count = (bit<8>)count;
		get_node_seq_bl_bh_index();
		block_count.read(count, meta.block_metadata.node_seq);
		hdr.udp.block_count = count;
		hdr.udp.pre_header_hash = meta.block_metadata.pre_header_hash;
		hdr.udp.curr_header_hash = meta.block_metadata.curr_header_hash;
		hdr.udp.data_hash = meta.block_metadata.data_hash;
		hdr.udp.timestamp = meta.block_metadata.timestamp;
		hdr.udp.nonce = meta.block_metadata.nonce;
	}


	//table debug {
	//	key = {
	//		standard_metadata.ingress_port: exact;
	//		standard_metadata.egress_port: exact;
	//	}
	//	actions = {
	//		NoAction;
	//	}
	//	size = 1024;
	//	default_action = NoAction();
	//}

    apply {
		@atomic{
			// step 1: initialize the genesis block
			// step 2: analysis the request type
			// step 3: if the request type is init, init the env and create genesis block

			if(hdr.ethernet.dstAddr[7:0] != 0xff){
				change_egress_port();
				change_request_type();
				drop();
				return;
			}

#if 1
			if((hdr.udp.request_type == INIT_REQUEST_L) || (hdr.udp.request_type == INIT_REQUEST_U)){
				if(standard_metadata.ingress_port == 1 && standard_metadata.egress_port == 0){
					init_nodes_count();    // init 2 nodes
					init_block_count();
					init_proof_of_work_register();
					multicast();
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
					output_to_hdr();
					read_block_from_list();
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
					forward_to_dest_port(1);
					output_to_hdr();
				}
			// step 5: if the request type is write, create a new block and return the new block header hash to user
			}else if((hdr.udp.request_type == WRITE_REQUEST_L) || (hdr.udp.request_type == WRITE_REQUEST_U)){
				// step 5.1: broadcast write request to all nodes
				// step 5.2: all nodes start to do proof of work
				// step 5.3: one node broadcast its result to other nodes
				// step 5.4: other nodes stop to send out packet
				// step 5.5: save the result and send header hash to user

				if(standard_metadata.ingress_port == 1){
					verify_failed_count.write(0, 0);
					verify_success_count.write(0, 0);
					init_proof_of_work_register();
					multicast();
				}else{
					// do proof of work job
					hdr.ipv4.ttl = 47;
					forward_to_dest_port(1);
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
							add_block_to_list();
							set_proof_of_work_register();
							resubmit(standard_metadata);
						}
					}else{
						// 0. if verify_success_count is bigger than half of nodes count, drop;
						bit<32> vs_count = 0;
						bit<32> vf_count = 0;
						verify_success_count.read(vs_count, 0);
						verify_failed_count.read(vf_count, 0);
						nodes_count.read(n_count, 0);
						if(vs_count > (n_count >> 1) || vf_count >= n_count){
							change_egress_port();
							change_request_type();
							drop();
							return;
						}
						// 1. read block from register done_list according verify_index;
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

							verify_index.read(d_index, 0);
							if(d_index >= n_count){
								change_egress_port();
								change_request_type();
								drop();
								return;
							}

							done_list.read(b_index, d_index);
							index = b_index % 1024;

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

							hdr.ipv4.ttl = 41;
							output_to_hdr();
							forward_to_dest_port(1);
						}else if(vf_count >= n_count){
							add_verify_index();
							forward_to_dest_port(1);
							standard_metadata.ingress_port = 1;
							verify_failed_count.write(0, 0);
							verify_success_count.write(0, 0);
							resubmit(standard_metadata);
						}else{
							change_egress_port();
							change_request_type();
							drop();
							return;
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
					if(standard_metadata.ingress_port != (((bit<9>)n_count * 2 + 1))){
						change_egress_port();
						change_request_type();
						drop();
						return;
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
							//copy_from_reg_to_reg_256(max_block_index, curr_node_index, 256);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 256);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 384);
						}
						if(max_block_count & 0x0200 != 0){
							//copy_from_reg_to_reg_512(max_block_index, curr_node_index, 512);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 512);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 640);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 768);
							copy_from_reg_to_reg_128(max_block_index, curr_node_index, 896);
						}
						// step 3: return block count
						block_count.read(tmp_count, n_count - 1);
						output_to_hdr();
						forward_to_dest_port(1);
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
#else
			get_sha256(72, TEST_STR);
			forward_to_dest_port(1);
			hdr.udp.pre_header_hash = meta.block_metadata.curr_header_hash;
			hdr.ipv4.ttl = 41;
#endif
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
			hdr.udp.nodes_count,
			hdr.udp.block_count,
	        hdr.udp.pre_header_hash,
	        hdr.udp.curr_header_hash,
			hdr.udp.data_hash,
			hdr.udp.timestamp,
			hdr.udp.nonce,
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
