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
#define MAX_KEY 32
#define NUM_SRV 6

#define OPTION1 8
#define OPTION2 4
#define OPTION3 2

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
    bit<2> op; //operator
    bit<2> isClone; 
    bit<8> id; //request id = packet id
    bit<8> keyNum; //key 개수, 송유진 학점
    bit<8> cutNum; //잘리는 패킷의 개수
    bit<32> cutIndex; //01001 어디서 잘리는지 알려주는 인덱스
    bit<32> shiftNum; //얼마나 shift할지 알려줌(계속 변동)
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

header clone_i2e_metadata_t { // clone ingress to egress !!
    bit<8>custom_tag;
    EthernetAddress srcAddr;
}

struct metadata_t {
    bit<32> cut_idx; //cutidx 저장하는 temp
    bit<8> key_num; //keynum 저장하는 temp
    bit<8> num_temp; //pkt에 keynum을 할당해줄 때 사용하는 temp
    bit<8> count_key_num; //value arr에서 사용하는 counter (패킷이 몇개 왔는지)
    bit<8> dst_srv_idx; //요청이 어떤 서버로 갈지
    bit<16> req_value; //요청(서버)에서 오는 value를 저장함, A+
    bit<2> do_ing_mirroring;  // Enable ingress mirroring
    bit<2> last_pkt; // last packet
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
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
        in  psa_ingress_input_metadata_t  istd, // clone 시 istd !!
        inout psa_ingress_output_metadata_t ostd) // clone 시 ostd !!
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

//해시 파티션이라서 라운드 로빈이 아니라 해시를 사용하기, 라운드 로빈은 복제 파티션... 

    action get_dst_srv_action(){
        ig_md.dst_srv_idx = hdr.keys[0]%NUM_SRV;
    }

    table get_dst_srv_table{
        actions = {
            get_dst_srv_action;
        }
        size = 1;
        default_action = get_dst_srv_action;
    }

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

    action left_shift_cutIndex_action(){
        hdr.netmc.cutIndex = hdr.netmc.cutIndex << hdr.netmc.shiftNum;
    }

    table left_shift_cutIndex_table{
        actions = {
            left_shift1_cutIndex_action;
        }
        size = 1;
        default_action = left_shift1_cutIndex_action;
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

    action get_keyNum_action(){
        ig_md.key_num = hdr.netmc.keyNum;
    }

    table get_keyNum_table {
        actions = {
            get_keyNum_action;
        }
        size = 1;
        default_action = get_keyNum_action;
    }

    action assign_keyNum_action(){
        if(hdr.netmc.isClone)
            ig_md.num_temp = hdr.netmc.keyNum - hdr.netmc.shiftNum;
        else
            ig_md.num_temp = hdr.netmc.shiftNum;
        hdr.netmc.keyNum = ig_md.num_temp;
    }

    table assign_keyNum_table {
        actions = {
            assign_keyNum_action;
        }
        size = 1;
        default_action = assign_keyNum_action;
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
        put_req_value.execute(hdr.netmc.id);
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

    action set_clone_action(){
        hdr.netmc.isClone = 1;
    }

    table set_clone_table {
        actions = {
            set_clone_action;
        }
        size = 1;
        default_action = set_clone_action;
    }

    action set_not_clone_action(){
        hdr.netmc.isClone = 0;
    }

    table set_not_clone_table {
        actions = {
            set_not_clone_action;
        }
        size = 1;
        default_action = set_not_clone_action;
    }

    action set_shiftNum_action(){
        if(hdr.netmc.cutIndex & 8)
            hdr.netmc.shiftNum = 1;
        else if(hdr.netmc.cutIndex & 4)
            hdr.netmc.shiftNum = 2;
        else if(hdr.netmc.cutIndex & 2)
            hdr.netmc.shiftNum = 3;
        else
            hdr.netmc.shiftNum = 0;
    }

    table set_shiftNum_table {
        actions = {
            set_shiftNum_action;
        }
        size = 1;
        default_action = set_shiftNum_action;
    }

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


//1. register 어떻게 넣는지 대충
//2. header 배열을 스택 형태로 넣어서 pop / push 하는 아이디어...?
//3. header drop key... -> setInvalid();
// setInvalid // pop // 접근법 다르게???

    apply {
        /*************** NetMC Block START *****************************/
        if(hdr.netmc.isValid()){
            if(hdr.netmc.op == OP_MULTIGET || hdr.netmc.op == OP_GET){
                if(hdr.netmc.op == OP_MULTIGET){
                    if(hdr.netmc.keyNum > 4){ //
                        get_key_num_table.apply();
                        left_shift_cutIndex_table.apply();
                        drop_key4_table.apply();
                        mirror_fwd_table.apply(); // -> do_clone_table.apply(); !!
                        right_shift4_cutIndex_table.apply(); 
                        
                        if(hdr.netmc.cutIndex % 2 != 1)
                            set_last_bit_table.apply();
                        assign_keyNum_table.apply();
                        drop_key4toN_table.apply();
                    }
                    if(hdr.netmc.keyNum <= 4){
                        set_shiftNum_table.apply();
                        if(hdr.netmc.shiftNum != 0){
                            left_shift_cutIndex_table.apply();
                            if(hdr.netmc.cutIndex != 0){  
                                set_clone_table.apply(); //
                                assign_keyNum_table.apply(); //
                                mirror_fwd_table.apply(); //
                            }
                            set_not_clone_table.apply(); //
                            drop_key_table.apply(); //
                            assign_keyNum_table.apply(); //
                        }
                    }
                }
                get_dst_srv_table.apply();
                get_dst_ip_table.apply();
            }
            else if(hdr.netmc.op == OP_G_REPLY || hdr.netmc.op == OP_MG_REPLY){
                if(hdr.netmc.op == OP_MG_REPLY){
                    check_last_pkt_table.apply();
                    if(ig_md.last_pkt == 1)
                        put_req_value_to_pkt_table.apply(); //
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
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        out clone_i2e_metadata_t clone_i2e_meta, // 수정 !!
        out empty_metadata_t resubmit_meta, // 수정 !!
        out metadata normal_meta, // 수정 !!
        in psa_ingress_output_metadata_t istd) { // 수정 !!
    
    DeparserImpl() common_deparser;

    apply {
        if (psa_clone_i2e(istd)) {
            clone_i2e_meta.custom_tag = (bit<8>) ig_md.custom_clone_id;
            if (ig_md.custom_clone_id == 1) {
                clone_i2e_meta.srcAddr = hdr.ethernet.srcAddr;
            }
        }
        common_deparser.apply(packet, hdr);
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