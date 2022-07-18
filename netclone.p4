#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#define OP_GET 0
#define OP_G_REPLY 1
#define OP_MULTIGET 2
#define OP_M_REPLY 3
#define MAX_NUM_REPLICA 8
#define NUM_OBJ 131072
#define NUM_HASH_TABLE 2 // MUST be 2^n for compile time computation
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> ether_type_t;
const ether_type_t TYPE_IPV4 = 0x800;
typedef bit<8> trans_protocol_t;
const trans_protocol_t TYPE_TCP = 6;
const trans_protocol_t TYPE_UDP = 17;
const bit<16> TYPE_NETMC = 4321; // NOT 0x1234

header ethernet_h {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header netmc_h { // Total 25 bytes actually
    bit<8> op;
    bit<4> cutIndex;
    bit<8> keyNum;
    bit<8> cutNum;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header tcp_h {
    bit<16> srcport;
    bit<16> dstport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}
struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    netmc_h netmc;
}

struct metadata_t {
    bit<16> cutIndexM;
    bit<16> num_srv_small;
    bit<16> num_srv_large;
    bit<2> found;
    bit<32> oid_hash;
    bit<32> hashtablenum;
    bit<8> DstSrvIdx;
    bit<8> DstSrvIdxSmall;
    bit<32> threshold;
    bit<2> large;
}

struct custom_metadata_t {

}

struct empty_header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    netmc_h netmc;
}

struct empty_metadata_t {
    custom_metadata_t custom_metadata;
}

Register<bit<32>,_>(NUM_OBJ,0) rset;
Register<bit<32>,_>(NUM_OBJ,0) rset2;
Register<bit<32>,_>(NUM_OBJ,0) rset3;
Register<bit<32>,_>(NUM_OBJ,0) rset4;
Register<bit<16>,_>(1,0) DstSrvIdx_small; // result of round robin
Register<bit<16>,_>(1,0) DstSrvIdx_large; // result of round robin
Register<bit<8>,_>(1,0) num_srv_small;
Register<bit<8>,_>(1,0) num_srv_large;
Register<bit<16>,_>(1,0) threshold;
Register<bit<32>,_>(1,0) hashtablenum;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        //transition parse_netmc;
        transition select(hdr.udp.dstPort){
            TYPE_NETMC: parse_netmc;
            default: accept;
        }
    }

    state parse_netmc {
        pkt.extract(hdr.netmc);
        transition accept;
    }

}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {




    action drop() {
        ig_intr_dprsr_md.drop_ctl=1;
    }

    action ipv4_forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    //@pragma stage 6
    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 16;
       default_action = drop();
    }

    table ipv4_exact_netmc {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 16;
       default_action = drop();
    }



    RegisterAction<bit<16>, _, bit<16>>(DstSrvIdx_small) get_dst_srv_small_rr = {
        void apply(inout bit<16> reg_value, out bit<16> return_value) {
            return_value = reg_value;
            if(reg_value >= ig_md.num_srv_small - 1)
                reg_value = 0;
            else
                reg_value = reg_value + 1;
        }
    };

    action get_dst_srv_small_rr_action(){
        ig_md.DstSrvIdxSmall = (bit<8>)get_dst_srv_small_rr.execute(0);
    }

    table get_dst_srv_small_rr_table{
        actions = {
            get_dst_srv_small_rr_action;
        }
        size = 1;
        default_action = get_dst_srv_small_rr_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(DstSrvIdx_large) get_dst_srv_large_rr = {
        void apply(inout bit<16> reg_value, out bit<16> return_value) {
            return_value = reg_value;
            if(reg_value >= ig_md.num_srv_large - 1)
                reg_value = 0;
            else
                reg_value = reg_value + 1;
        }
    };

    action get_dst_srv_large_rr_action(){
        ig_md.DstSrvIdx = (bit<8>)get_dst_srv_large_rr.execute(0);
    }

    table get_dst_srv_large_rr_table{
        actions = {
            get_dst_srv_large_rr_action;
        }
        size = 1;
        default_action = get_dst_srv_large_rr_action;
    }


    RegisterAction<bit<32>, _, bit<32>>(rset) get_rset = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            if (reg_value == hdr.netmc.oid)
                return_value = 1;
            else
                return_value = 0;
        }
    };
    action get_rset_action(){
        ig_md.found = (bit<2>)get_rset.execute(ig_md.oid_hash);
    }
    table get_rset_table{
        actions = {
            get_rset_action;
        }
        size = 1;
        default_action = get_rset_action;
    }



    RegisterAction<bit<32>, _, bit<32>>(rset2) get_rset2 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            if (reg_value == hdr.netmc.oid)
                return_value = 1;
            else
                return_value = 0;
        }
    };
    action get_rset2_action(){
        ig_md.found = (bit<2>)get_rset2.execute(ig_md.oid_hash);
    }
    table get_rset2_table{
        actions = {
            get_rset2_action;
        }
        size = 1;
        default_action = get_rset2_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset3) get_rset3 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            if (reg_value == hdr.netmc.oid)
                return_value = 1;
            else
                return_value = 0;
        }
    };
    action get_rset3_action(){
        ig_md.found = (bit<2>)get_rset3.execute(ig_md.oid_hash);
    }
    table get_rset3_table{
        actions = {
            get_rset3_action;
        }
        size = 1;
        default_action = get_rset3_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset4) get_rset4 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            if (reg_value == hdr.netmc.oid)
                return_value = 1;
            else
                return_value = 0;
        }
    };
    action get_rset4_action(){
        ig_md.found = (bit<2>)get_rset4.execute(ig_md.oid_hash);
    }
    table get_rset4_table{
        actions = {
            get_rset4_action;
        }
        size = 1;
        default_action = get_rset4_action;
    }


    RegisterAction<bit<16>, _, bit<16>>(num_srv_small) get_num_srv_small = {
        void apply(inout bit<16> reg_value, out bit<16> return_value) {
            return_value = reg_value;
        }
    };

    action get_num_srv_small_action(){
        ig_md.num_srv_small = get_num_srv_small.execute(0);
    }

    table get_num_srv_small_table{
        actions = {
            get_num_srv_small_action;
        }
        size = 1;
        default_action = get_num_srv_small_action;
    }


    RegisterAction<bit<16>, _, bit<16>>(num_srv_large) get_num_srv_large = {
        void apply(inout bit<16> reg_value, out bit<16> return_value) {
            return_value = reg_value;
        }
    };

    action get_num_srv_large_action(){
        ig_md.num_srv_large = get_num_srv_large.execute(0);
    }

    table get_num_srv_large_table{
        actions = {
            get_num_srv_large_action;
        }
        size = 1;
        default_action = get_num_srv_large_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset) put_rset = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
                reg_value = hdr.netmc.oid;
        }
    };
    action put_rset_action(){
        put_rset.execute(ig_md.oid_hash);
    }
    table put_rset_table{
        actions = {
            put_rset_action;
        }
        size = 1;
        default_action = put_rset_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset2) put_rset2 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            reg_value = hdr.netmc.oid;
        }
    };
    action put_rset2_action(){
        put_rset2.execute(ig_md.oid_hash);
    }
    table put_rset2_table{
        actions = {
            put_rset2_action;
        }
        size = 1;
        default_action = put_rset2_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset3) put_rset3 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            reg_value = hdr.netmc.oid;
        }
    };
    action put_rset3_action(){
        put_rset3.execute(ig_md.oid_hash);
    }
    table put_rset3_table{
        actions = {
            put_rset3_action;
        }
        size = 1;
        default_action = put_rset3_action;
    }

    RegisterAction<bit<32>, _, bit<32>>(rset4) put_rset4 = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            reg_value = hdr.netmc.oid;
        }
    };
    action put_rset4_action(){
        put_rset4.execute(ig_md.oid_hash);
    }
    table put_rset4_table{
        actions = {
            put_rset4_action;
        }
        size = 1;
        default_action = put_rset4_action;
    }

    action get_hash_action(){
        ig_md.oid_hash = hdr.netmc.oid%NUM_OBJ;
        //ig_md.oid_hash = hdr.netmc.oid;
    }


    //@pragma stage 2
    table get_hash_table{
        actions = {
            get_hash_action;
        }
        size = 1;
        default_action = get_hash_action;
    }


    RegisterAction<bit<32>, _, bit<32>>(hashtablenum) get_hashtablenum = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            return_value = reg_value;
            if (reg_value >= NUM_HASH_TABLE -1)
                reg_value = 0;
            else
                reg_value = reg_value + 1;

        }
    };

    action assign_threshold_action(){
        hdr.netmc.valsize = ig_md.threshold;
    }

    table assign_threshold_table{
        actions = {
            assign_threshold_action;
        }
        size = 1;
        default_action = assign_threshold_action;
    }

    action get_hashtablenum_action(){
        ig_md.hashtablenum = hdr.netmc.oid%NUM_HASH_TABLE;
    }

    table get_hashtablenum_table{
        actions = {
            get_hashtablenum_action;
        }
        size = 1;
        default_action = get_hashtablenum_action;
    }


    action get_dst_ip_action(bit<32> addr,bit<9> port){
        hdr.ipv4.dstAddr = addr;
        ig_tm_md.ucast_egress_port = port;
    }

    //@pragma stage 2
    table get_dst_ip_small_table{
        key = {
            ig_md.DstSrvIdxSmall: exact;
        }
        actions = {
            get_dst_ip_action;
        }
        size = 16;
        default_action = get_dst_ip_action(0,0x0);
    }




    //@pragma stage 2
    table get_dst_ip_large_table{
        key = {
            ig_md.DstSrvIdx: exact;
        }
        actions = {
            get_dst_ip_action;
        }
        size = 16;
        default_action = get_dst_ip_action(0,0x0);
    }
    RegisterAction<bit<32>, _, bit<32>>(threshold) get_threshold = {
        void apply(inout bit<32> reg_value, out bit<32> return_value) {
            return_value = reg_value;
        }
    };

    action get_threshold_action(){
        ig_md.threshold = get_threshold.execute(0);
    }

    table get_threshold_table{
        actions = {
            get_threshold_action;
        }
        size = 1;
        default_action = get_threshold_action;
    }


    apply {
        /*************** NetLR Block START *****************************/
            if (hdr.netclone.isValid()){
                get_threshold_table.apply(); // Save th. to ig_md.threshold
                get_hash_table.apply();
                get_hashtablenum_table.apply();
                if (hdr.netclone.op == OP_READ || hdr.netclone.op == OP_WRITE){
                    assign_threshold_table.apply();
                    get_rset_table.apply();
                    /*if(ig_md.found == 0)
                        get_rset2_table.apply();
                    if(ig_md.found == 0)
                        get_rset3_table.apply();
                    if(ig_md.found == 0)
                        get_rset4_table.apply();
                    */
                    if(ig_md.found == 1){
                        get_num_srv_large_table.apply(); // 2
                        get_dst_srv_large_rr_table.apply();
                        get_dst_ip_large_table.apply();
                    }
                    else if(ig_md.found == 0){
                        get_num_srv_small_table.apply(); // 1
                        get_dst_srv_small_rr_table.apply();
                        get_dst_ip_small_table.apply();
                    }
                }
                else if(hdr.netclone.op == OP_R_REPLY || hdr.netclone.op == OP_W_REPLY){
                    if (hdr.netclone.valsize == 1){
                        put_rset_table.apply();

                        /*if (ig_md.hashtablenum == 0)
                            put_rset_table.apply();
                        /*else if(ig_md.hashtablenum == 1)
                            put_rset2_table.apply();
                        else if(ig_md.hashtablenum == 2)
                            put_rset3_table.apply();
                        else if(ig_md.hashtablenum == 3)
                            put_rset4_table.apply();*/
                    }
                    ipv4_exact_netclone.apply();
                }

            }
            else
                ipv4_exact.apply();
    }
}



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser SwitchEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

control SwitchEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {

    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;