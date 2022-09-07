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

#define NUM_OBJ 131072
#define MAX_KEY 8
#define NUM_SRV 4

#define OPTION1 32768
#define OPTION2 16384
#define OPTION3 8192

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> ether_type_t;
const ether_type_t TYPE_IPV4 = 0x800;
typedef bit<8> trans_protocol_t;
const trans_protocol_t TYPE_TCP = 6;
const trans_protocol_t TYPE_UDP = 17;
const bit<16> TYPE_NETMC = 4321; // NOT 0x1234
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;

header ethernet_h {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header key_h {
    bit<16> key;
    bit<32> oid;
}

header value_h {
    bit<16> value;
}

header netmc_h { // Total 25 bytes actually
    bit<8> op; //operator
    bit<16> id; //request id = packet id
    bit<16> firstCut;
    bit<16> lastCut;
    bit<16> keyNum; //key 개수, 송유진 학점
    bit<16> cutNum; //잘리는 패킷의 개수
    bit<16> cutIndex; //01001 어디서 잘리는지 알려주는 인덱스
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
    key_h[MAX_KEY] keys;
    value_h[MAX_KEY] values;
}

/*
header clone_i2e_metadata_t { // clone ingress to egress !!
    bit<8>custom_tag;
    bit<16> srcAddr;
}
*/

struct metadata_t {
    bit<1> do_ing_mirroring;  // Enable ingress mirroring
    bit<1> do_egr_mirroring;  // Enable egress mirroring
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
    bit<16> count_invalid; 
    bit<16> chk_keyNum; 
    bit<16> cut_idx; //cutidx 저장하는 temp
    bit<16> key_num; //keynum 저장하는 temp
    bit<16> count_key_num; //value arr에서 사용하는 counter (패킷이 몇개 왔는지)
    bit<16> req_value; //요청(서버)에서 오는 value를 저장함, A+
    bit<16> last_pkt; // last packet
    bit<16> req_id; 
    bit<32> dst_srv_idx; //요청이 어떤 서버로 갈지
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

Register<bit<8>,_>(NUM_OBJ,0) count_key_num; //countArr 레지스터 최소 8, 최대 32비트
Register<bit<16>,_>(NUM_OBJ,0) req_value; //valueArr 
Register<bit<16>,_>(1,0) dst_srv_idx; // result of hash server
Register<bit<16>,_>(1,0) pkt_idx;

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

    state parse_keys {
        pkt.extract(hdr.keys.next);
        transition accept;
    }

    state parse_values {
        pkt.extract(hdr.values.next);
        transition accept;
        
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
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
        //in  psa_ingress_input_metadata_t  istd, // clone 시 istd !!
        //inout psa_ingress_output_metadata_t ostd) // clone 시 ostd !!
{

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

    action get_dst_srv_action(){
        ig_md.dst_srv_idx = hdr.keys[0].oid%NUM_SRV; 
    }

    table get_dst_srv_table{
        actions = {
            get_dst_srv_action;
        }
        size = 1;
        default_action = get_dst_srv_action;
    }

    action get_dst_ip_action(bit<32> addr, bit<9> port){
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

    action left_shift_cutIndex1_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 1;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 1;
    }

    table left_shift_cutIndex1_table{
        actions = {
            left_shift_cutIndex1_action;
        }
        size = 1;
        default_action = left_shift_cutIndex1_action;
    }

    action left_shift_cutIndex2_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 2;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 2;
    }

    table left_shift_cutIndex2_table{
        actions = {
            left_shift_cutIndex2_action;
        }
        size = 1;
        default_action = left_shift_cutIndex2_action;
    }

    action left_shift_cutIndex3_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 3;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 3;
    }

    table left_shift_cutIndex3_table{
        actions = {
            left_shift_cutIndex3_action;
        }
        size = 1;
        default_action = left_shift_cutIndex3_action;
    }

    action left_shift_cutIndex4_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << 4;
        hdr.netmc.keyNum = hdr.netmc.keyNum - 4;
    }

    table left_shift_cutIndex4_table{
        actions = {
            left_shift_cutIndex4_action;
        }
        size = 1;
        default_action = left_shift_cutIndex4_action;
    }

    action set_mirror_type() {
        ig_intr_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
    }
    
    action mirror_fwd_action(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_tm_md.ucast_egress_port = dest_port;
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
    }

    table mirror_fwd_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            mirror_fwd_action;
        }
        size = 1;
    }

    action mirror_clone_fwd_action(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_tm_md.ucast_egress_port = dest_port;
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
    }

    table mirror_clone_fwd_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            mirror_clone_fwd_action;
        }
        size = 1;
    }

    action set_drop_first_index_action(){   
        hdr.netmc.firstCut = 4 - hdr.netmc.keyNum;
    }

    table set_drop_first_index_table {
        actions = {
            set_drop_first_index_action;
        }
        size = 1;
        default_action = set_drop_first_index_action;
    }

    action set_drop_last_index_action(){   
        hdr.netmc.lastCut = hdr.netmc.firstCut + hdr.netmc.keyNum;
        //hdr.netmc.lastCut = hdr.netmc.lastCut - 1;
    }

    table set_drop_last_index_table {
        actions = {
            set_drop_last_index_action;
        }
        size = 1;
        default_action = set_drop_last_index_action;
    }

    action set_drop_clone_index_action(){
        hdr.netmc.firstCut = 4 - hdr.netmc.keyNum;
        hdr.netmc.lastCut = hdr.netmc.firstCut + hdr.netmc.keyNum - 1;
    }

    table set_drop_clone_index_table {
        actions = {
            set_drop_clone_index_action;
        }
        size = 1;
        default_action = set_drop_clone_index_action;
    }

    action get_keyNum_action(){
        ig_md.key_num = hdr.netmc.keyNum;
        ig_md.cut_idx = hdr.netmc.cutIndex;
    }

    table get_keyNum_table {
        actions = {
            get_keyNum_action;
        }
        size = 1;
        default_action = get_keyNum_action;
    }

    action update_clone_keyNum_action(){
        hdr.netmc.keyNum = 4;
    }

    table update_clone_keyNum_table {
        actions = {
            update_clone_keyNum_action;
        }
        size = 1;
        default_action = update_clone_keyNum_action;
    }

    action drop_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex & 61440;
    }
    
    table drop_cutIndex_table{
        actions = {
            drop_cutIndex_action;
        }
        size = 1;
        default_action = drop_cutIndex_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(count_key_num) update_arrived_key_num = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            reg_value = reg_value + 1;
            return_value = reg_value;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(count_key_num) get_count_key_num = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
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

    action get_req_id(){
        ig_md.req_id = hdr.netmc.id*8;
        ig_md.count_key_num = get_count_key_num.execute(hdr.netmc.id);
    }

    action put_req_value_action(){
        ig_md.req_id = ig_md.count_key_num+ig_md.req_id;
        put_req_value.execute(ig_md.req_id);
    }

    table put_req_value_table {
        actions = {
            put_req_value_action;
        }
        size = 1;
        default_action = put_req_value_action;
    }

    action set_last_bit_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex | 1;
    }

    table set_last_bit_table {
        actions = {
            set_last_bit_action;
        }
        size = 1;
        default_action = set_last_bit_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(req_value) put_req_value_to_pkt = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            return_value = reg_value;
        }
    };

    action put_req_value_to_pkt1_action(){
        hdr.values[0].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt2_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[1].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt3_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[2].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt4_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[3].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt5_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[4].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt6_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[5].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt7_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[6].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    action put_req_value_to_pkt8_action(){
        ig_md.req_id = ig_md.req_id+1;
        hdr.values[7].value = put_req_value_to_pkt.execute(ig_md.req_id);
    }

    table put_req_value_to_pkt1_table {
        actions = {
            put_req_value_to_pkt1_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt1_action;
    }

    table put_req_value_to_pkt2_table {
        actions = {
            put_req_value_to_pkt2_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt2_action;
    }

    table put_req_value_to_pkt3_table {
        actions = {
            put_req_value_to_pkt3_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt3_action;
    }

    table put_req_value_to_pkt4_table {
        actions = {
            put_req_value_to_pkt4_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt4_action;
    }

    table put_req_value_to_pkt5_table {
        actions = {
            put_req_value_to_pkt5_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt5_action;
    }

    table put_req_value_to_pkt6_table {
        actions = {
            put_req_value_to_pkt6_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt6_action;
    }

    table put_req_value_to_pkt7_table {
        actions = {
            put_req_value_to_pkt7_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt7_action;
    }

    table put_req_value_to_pkt8_table {
        actions = {
            put_req_value_to_pkt8_action;
        }
        size = 1;
        default_action = put_req_value_to_pkt8_action;
    }

    action check_last_pkt_action(){
        ig_md.last_pkt = hdr.netmc.cutNum - ig_md.count_key_num;
    }

    table check_last_pkt_table {
        actions = {
            check_last_pkt_action;
        }
        size = 1;
        default_action = check_last_pkt_action;
    }

    action is_keyNum4_action(){
        ig_md.chk_keyNum = hdr.netmc.keyNum;
        ig_md.chk_keyNum = ig_md.chk_keyNum - 4;
    }

    table is_keyNum4_table {
        actions = {
            is_keyNum4_action;
        }
        size = 1;
        default_action = is_keyNum4_action;
    }

    action update_keyNum1_action(){
        hdr.netmc.keyNum = 1;
    }

    table update_keyNum1_table {
        actions = {
            update_keyNum1_action;
        }
        size = 1;
        default_action = update_keyNum1_action;
    }

    action update_keyNum2_action(){
        hdr.netmc.keyNum = 2;
    }

    table update_keyNum2_table {
        actions = {
            update_keyNum2_action;
        }
        size = 1;
        default_action = update_keyNum2_action;
    }

    action update_keyNum3_action(){
        hdr.netmc.keyNum = 3;
    }

    table update_keyNum3_table {
        actions = {
            update_keyNum3_action;
        }
        size = 1;
        default_action = update_keyNum3_action;
    }

/*
    // 복제 과정 !!
    action do_clone_action (CloneSessionId_t session_id) { // 
        ostd.clone = true;
        ostd.clone_session_id = session_id;
        id_md.custom_clone_id = 1;
    }
    table do_clone_table {
        key = {
            id_md.fwd_metadata.outport : exact;
        }
        actions = { do_clone_action; }
    }
*/

    apply {
        /*************** NetMC Block START *****************************/
        if(hdr.netmc.isValid()){
            if(hdr.netmc.op == OP_MULTIGET || hdr.netmc.op == OP_GET){
                if(hdr.netmc.op == OP_MULTIGET){
                    is_keyNum4_table.apply();
                    if(ig_md.chk_keyNum > 0){ 
                        get_keyNum_table.apply(); //replicated
                        left_shift_cutIndex4_table.apply();

                        mirror_clone_fwd_table.apply();
                        set_mirror_type();

                        drop_cutIndex_table.apply(); //original
                        if((hdr.netmc.cutIndex & 1) == 1)
                            set_last_bit_table.apply();
                        update_clone_keyNum_table.apply();
                    }
                    if(ig_md.chk_keyNum <= 0){
                        if((hdr.netmc.cutIndex & OPTION1) == 1)
                            left_shift_cutIndex1_table.apply();
                        else if((hdr.netmc.cutIndex & OPTION2) == 1)
                            left_shift_cutIndex2_table.apply();
                        else if((hdr.netmc.cutIndex & OPTION3) == 1)
                            left_shift_cutIndex3_table.apply();
                            
                        if(hdr.netmc.cutIndex != 0){
                            mirror_fwd_table.apply();
                            set_mirror_type();
                        }
                        if((hdr.netmc.cutIndex & OPTION1) == 1)
                            update_keyNum1_table.apply();
                        else if((hdr.netmc.cutIndex & OPTION2) == 1)
                            update_keyNum2_table.apply();
                        else if((hdr.netmc.cutIndex & OPTION3) == 1)
                            update_keyNum3_table.apply();

                        set_drop_first_index_table.apply();
                        set_drop_last_index_table.apply();
                    }
                }
                get_dst_srv_table.apply();
                get_dst_ip_table.apply();
            }
            else if(hdr.netmc.op == OP_G_REPLY || hdr.netmc.op == OP_MG_REPLY){
                if(hdr.netmc.op == OP_MG_REPLY){
                    check_last_pkt_table.apply();
                    if(ig_md.last_pkt == 1){
                        get_req_id();
                        put_req_value_to_pkt1_table.apply(); 
                        put_req_value_to_pkt2_table.apply(); 
                        put_req_value_to_pkt3_table.apply(); 
                        put_req_value_to_pkt4_table.apply(); 
                        put_req_value_to_pkt5_table.apply(); 
                        put_req_value_to_pkt6_table.apply(); 
                        put_req_value_to_pkt7_table.apply(); 
                        put_req_value_to_pkt8_table.apply(); 
                    }
                    else{
                        get_req_id();
                        put_req_value_table.apply(); 
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

        //out clone_i2e_metadata_t clone_i2e_meta, // 수정 !!
        //out empty_metadata_t resubmit_meta, // 수정 !!
        //out metadata normal_meta, // 수정 !!
        //in psa_ingress_output_metadata_t istd) { // 수정 !!
    
    //DeparserImpl() common_deparser;

    apply {/*
        if (psa_clone_i2e(istd)) {
            clone_i2e_meta.custom_tag = (bit<8>) ig_md.custom_clone_id;
            if (ig_md.custom_clone_id == 1) {
                clone_i2e_meta.srcAddr = hdr.ethernet.srcAddr;
            }
        }
        common_deparser.apply(packet, hdr);*/

        pkt.emit(hdr); // 원래는 이 코드 하나만 apply 안에 있었음
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