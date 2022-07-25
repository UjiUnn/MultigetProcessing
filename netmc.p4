#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#define OP_GET 0
#define OP_G_REPLY 1
#define OP_MULTIGET 2
#define OP_MG_REPLY 3
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

header key_h {
    bit<16> key;
}

header value_h {
    bit<16> value;
}

header netmc_h { // Total 25 bytes actually
    bit<2> op;
    bit<8> id;
    bit<32> cutIndex;
    bit<6> keyNum;
    bit<6> cutNum;
    key_h[32] keys;
    value_h[32] values;
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
    bit<6> count_key_num;
    bit<16> req_value;
    bit<32> cut_idx;
    bit<6> key_num;
    bit<8> dst_srv_idx;
    bit<1> do_ing_mirroring;  // Enable ingress mirroring
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

Register<bit<6>,_>(NUM_OBJ,0) count_key_num; //countArr
Register<bit<16>,_>(NUM_OBJ,0) req_value; //valueArr 
Register<bit<16>,_>(1,0) dst_srv_idx; // result of round robin

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

    RegisterAction<bit<16>, _, bit<16>>(DstSrvIdx) get_dst_srv_rr = {
        void apply(inout bit<16> reg_value, out bit<16> return_value) {
            return_value = reg_value;
            if(reg_value >= ig_md.num_srv - 1)
                reg_value = 0;
            else
                reg_value = reg_value + 1;
        }
    };

    action get_dst_srv_rr_action(){
        ig_md.dst_srv_idx = (bit<8>)get_dst_srv_rr.execute(0);
    }

    table get_dst_srv_rr_table{
        actions = {
            get_dst_srv_rr_action;
        }
        size = 1;
        default_action = get_dst_srv_rr_action;
    }

    action get_hash_action(){
        ig_md.oid_hash = hdr.netmc.oid%NUM_OBJ;
        //ig_md.oid_hash = hdr.netmc.oid;
    }

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

    action get_dst_ip_action(bit<32> addr,bit<9> port){
        hdr.ipv4.dstAddr = addr;
        ig_tm_md.ucast_egress_port = port;
    }

    table get_dst_ip_table{
        key = {
            ig_md.dst_srv_idx: exact;
        }
        actions = {
            get_dst_ip_action;
        }
        size = 16;
        default_action = get_dst_ip_action(0,0x0);
    }

    action left_shift1_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 1;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 1;
    }

    table left_shift1_cutIndex_table{
        actions = {
            left_shift1_cutIndex_action;
        }
        size = 1;
        default_action = left_shift1_cutIndex_action;
    }

    action left_shift2_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 2;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 2;
    }

    table left_shift2_cutIndex_table{
        actions = {
            left_shift2_cutIndex_action;
        }
        size = 1;
        default_action = left_shift2_cutIndex_action;
    }

    action left_shift3_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 3;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 3;
    }

    table left_shift3_cutIndex_table{
        actions = {
            left_shift3_cutIndex_action;
        }
        size = 1;
        default_action = left_shift3_cutIndex_action;
    }

    action left_shift4_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 4;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 4;
    }

    table left_shift4_cutIndex_table{
        actions = {
            left_shift4_cutIndex_action;
        }
        size = 1;
        default_action = left_shift4_cutIndex_action;
    }

    action mirror_fwd_action(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_tm_md.ucast_egress_port = dest_port;
        ig_md.do_ing_mirroring = ing_mir;
        //ig_md.ing_mir_ses = ing_ses;
        hdr.bridged_md.do_egr_mirroring = egr_mir;
        hdr.bridged_md.egr_mir_ses = egr_ses;
    }

    table mirror_fwd_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            mirror_fwd_action;
        }
        size = 512;
        default_action = mirror_fwd_action;
    }

    action drop_key1toN_action(){
        hdr.netmc.keys.pop(hdr.netmc.keyNum-2);
    }

    table drop_key1toN_table {
        actions = {
            drop_key1toN_action;
        }
        size = 1;
        default_action = drop_key1toN_action;
    }

    action drop_key2toN_action(){
        hdr.netmc.keys.pop(hdr.netmc.keyNum-3);
    }

    table drop_key2toN_table {
        actions = {
            drop_key2toN_action;
        }
        size = 1;
        default_action = drop_key2toN_action;
    }

    action drop_key_action(){
        hdr.netmc.keys.pop();
    }

    table drop_key_table {
        actions = {
            drop_key_action;
        }
        size = 1;
        default_action = drop_key_action;
    }

    action drop_key4toN_action(){
        hdr.netmc.keys.pop(hdr.netmc.keyNum-5);
    }

    table drop_key4toN_table {
        actions = {
            drop_key4toN_action;
        }
        size = 1;
        default_action = drop_key4toN_action;
    }


    action drop_key4_action(){
        hdr.netmc.keys.pop_front(4);
    }

    table drop_key4_table {
        actions = {
            drop_key4_action;
        }
        size = 1;
        default_action = drop_key4_action;
    }

    action get_cut_idx_action(){
        ig_md.cut_idx = hdr.netmc.cutIndex;
    }

    table get_cut_idx_table {
        actions = {
            get_cut_idx_action;
        }
        size = 1;
        default_action = get_cut_idx_action;
    }

    action get_key_num_action(){
        ig_md.key_num = hdr.netmc.keyNum;
    }

    table get_key_num_table {
        actions = {
            get_key_num_action;
        }
        size = 1;
        default_action = get_key_num_action;
    }

    action assign_keyNum1_action(){
        hdr.netmc.keyNum = hdr.netmc.keyNum - 1;
    }

    table assign_keyNum1_table {
        actions = {
            assign_keyNum1_action;
        }
        size = 1;
        default_action = assign_keyNum1_action;
    }

    action assign_keyNum2_action(){
        hdr.netmc.keyNum = hdr.netmc.keyNum - 2;
    }

    table assign_keyNum2_table {
        actions = {
            assign_keyNum2_action;
        }
        size = 1;
        default_action = assign_keyNum2_action;
    }
    
    action assign_keyNum3_action(){
        hdr.netmc.keyNum = hdr.netmc.keyNum - 3;
    }

    table assign_keyNum3_table {
        actions = {
            assign_keyNum3_action;
        }
        size = 1;
        default_action = assign_keyNum3_action;
    }
    
    action assign_keyNum4_action(){
        hdr.netmc.keyNum = hdr.netmc.keyNum - 4;
    }

    table assign_keyNum4_table {
        actions = {
            assign_keyNum4_action;
        }
        size = 1;
        default_action = assign_keyNum4_action;
    }

    action right_shift4_cutIndex_action(){
        ig_md.cutIndex = ig_md.cutIndex >> (ig_md.keyNum - 4);
    }

    table right_shift4_cutIndex_table{
        actions = {
            right_shift4_cutIndex_action;
        }
        size = 1;
        default_action = right_shift4_cutIndex_action;
    }

    action add_4bits_action(){
        hd.netmc.cutIndex = (bit<4>)ig_md.cutIndex 4 bits;
    }

    table add_4bits_table{
        actions = {
            add_4bits_action;
        }
        size = 1;
        default_action = add_4bits_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(count_key_num) update_arrived_key_num = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            reg_value = reg_value + 1;
            return_value = reg_value;
        }
    };

    action update_arrived_key_num_action(){
        ig_md.count_key_num = update_arrived_key_num.execute(hdr.netmc.id);
    }

    table update_arrived_key_num_table {
        actions = {
            update_arrived_key_num_action;
        }
        size = 1;
        default_action = update_arrived_key_num_action;
    }
    
    RegisterAction<bit<16>, _, bit<16>>(req_value) put_req_value = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            reg_value = ig_md.req_value;
        }
    };

    action put_req_value_action(){
        //put_req_value.execute(hdr.netmc.cutNum);
    }

    table put_req_value_table {
        actions = {
            put_req_value_action;
        }
        size = 1;
        default_action = put_req_value_action;
    }

    action drop_cut_idx_action(){
        hdr.netmc.cutIndex.setInvalid();
    }

    table drop_cut_idx_table {
        actions = {
            drop_cut_idx_action;
        }
        size = 1;
        default_action = drop_cut_idx_action;
    }

    action set_last_bit_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex || 0001;
    }

    table set_last_bit_table {
        actions = {
            set_last_bit_action;
        }
        size = 1;
        default_action = set_last_bit_action;
    }

    action put_req_value_to_pkt_action(){
        hdr.netmc.values.push_front(hdr.netmc.keyNum);
        hdr.netmc.values = {ig_md.req_value};
    }

    table put_req_value_to_pkt_table {
        actions = {
            put_req_value_to_pkt_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt_action;
    }

//1. register 어떻게 넣는지 대충
//2. header 배열을 스택 형태로 넣어서 pop / push 하는 아이디어...?
//3. header drop key... -> setInvalid();
// setInvalid // pop // 접근법 다르게???

    apply {
        /*************** NetMC Block START *****************************/
        if(hdr.netmc.isValid()){
            if(hdr.netmc.op == OP_MULTIGET || hdr.netmc.op == OP_GET){
                if(hdr.netmc.op == OP_MULTIGET){
                    if(hdr.netmc.keyNum > 4){
                        get_cut_idx_table.apply();
                        get_key_num_table.apply();
                        left_shift4_cutIndex_table.apply();
                        drop_key4_table.apply();
                        mirror_fwd_table.apply(); //

                        right_shift4_cutIndex_table.apply(); 
                        drop_cut_idx_table.apply(); 
                        add_4bits_table.apply(); 
                        
                        if(hdr.netmc.cutIndex % 2 != 1)
                            set_last_bit_table.apply();
                        assign_keyNum4_table.apply();
                        drop_key4toN_table.apply();
                    }
                    if(hdr.netmc.keyNum <= 4){
                        if(hdr.netmc.cutIndex >= 8){
                            left_shift1_cutIndex_table.apply();
                            if(hdr.netmc.cutIndex != 0)                    
                                mirror_fwd_table.apply();
                            drop_key1toN_table.apply();
                            assign_keyNum1_table.apply();
                            
                        }
                        else if(hdr.netmc.cutIndex >= 4){
                            left_shift2_cutIndex_table.apply();
                            if(hdr.netmc.cutIndex != 0)
                                mirror_fwd_table.apply();
                            drop_key2toN_table.apply();
                            assign_keyNum2_table.apply();
                        }
                        else if(hdr.netmc.cutIndex >= 2){
                            left_shift3_cutIndex_table.apply();
                            if(hdr.netmc.cutIndex != 0)
                                mirror_fwd_table.apply();
                            drop_key_table.apply();     
                            assign_keyNum3_table.apply();
                        }
                    }
                }
                get_dst_srv_rr_table.apply();
                get_dst_ip_table.apply();
            }
            else if(hdr.netmc.op == OP_G_REPLY || hdr.netmc.op == OP_MG_REPLY){
                if(hdr.netmc.op == OP_MG_REPLY){
                    if((hdr.netmc.cutNum - ig_md.count_key_num) == 1)
                        put_req_value_to_pkt_table.apply();
                    else{
                        put_req_value_table.apply(); //
                        update_arrived_key_num_table.apply();
                    }
                }
                ipv4_exact_netmc.apply();
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