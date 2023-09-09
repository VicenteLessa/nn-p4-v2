/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define ET_ANN 0x88B5
#define FUNC_WEIGHTED_SUM 1
#define FUNC_IDENTITY 2
#define FUNC_RELU 3
#define FUNC_ARGMAX 4
#define FUNC_NORMALIZATION 5

#define PRECISION 16
#define WORDSIZE 32
#define D_WORDSIZE 64
#define SLACK 8

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

header ann_t {
bit<32> neuron_id;
bit<WORDSIZE> data_1;
bit<WORDSIZE> data_2;
bit<16> run_id;
bit<SLACK> slack;
}

struct metadata {
bit<32> neuron_id;            // temporarily stores the ID of the neuron in this switch.
bit<32> n_expected_stimuli;   // temporarily stores the number of expected stimuli by the neuron in a single ANN run.
bit<32> n_received_stimuli;   // temporarily stores the number of stimuli already received by the neuron in the current ANN run.
bit<128> expected_stimuli;    // temporarily stores a bitstring that indicates from which neurons is the neuron expected to receive stimuli. For example, if the bitstring has value 0b1010, the neuron is expected to receive stimuli from neurons with ID 1 and 3, but not from IDs 0 and 2.
bit<128> received_stimuli;    // temporarily stores a bitstring that indicates from which neurons is the neuron already received stimuli in the current ANN run.

bit<32> agg_func;
bit<32> activation_func;
bit<16> run_id;

bit<WORDSIZE> neuron_1_data;		//stores the data to be fowarded
bit<WORDSIZE> neuron_2_data;
bit<WORDSIZE> neuron_max_value;
bit<WORDSIZE> neuron_1_bias;
bit<WORDSIZE> neuron_2_bias;
bit<WORDSIZE> n2n_1_weight_1;
bit<WORDSIZE> n2n_1_weight_2;
bit<WORDSIZE> n2n_2_weight_1;
bit<WORDSIZE> n2n_2_weight_2;
bit<WORDSIZE> neuron_1_mean;
bit<WORDSIZE> neuron_2_mean;
bit<WORDSIZE> neuron_1_std;
bit<WORDSIZE> neuron_2_std;
}

struct headers {
ethernet_t   ethernet;
ann_t   ann;
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
        ET_ANN: parse_ann;
        default: accept;
    }
}

state parse_ann {
    packet.extract(hdr.ann);
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

register<bit<32>>(1) reg_n_received_stimuli;
register<bit<128>>(1) reg_received_stimuli;
register<bit<WORDSIZE>>(1) reg_neuron_1_data;
register<bit<WORDSIZE>>(1) reg_neuron_2_data;
register<bit<WORDSIZE>>(1) reg_neuron_max_value;
register<bit<16>>(1) reg_run_id;

    action drop(){
    mark_to_drop(standard_metadata);
}

action mcast(bit<16> mgroup){
    standard_metadata.mcast_grp = mgroup;
}

table ann_forward{
    key = {
        standard_metadata.ingress_port: exact;
    }
    actions = {
        mcast;
        drop;
    }
    size = 1024;
    default_action = drop();
}

action set_neuron_id(bit<32> neuron_id){
    meta.neuron_id = neuron_id;
}

table tab_neuron_id{
    actions = {
        set_neuron_id;
    }
    size = 1;
}

action set_n_expected_stimuli(bit<32> n_expected_stimuli){
    meta.n_expected_stimuli = n_expected_stimuli;
}

table tab_n_expected_stimuli{
    actions = {
        set_n_expected_stimuli;
    }
    size = 1;
}

action set_expected_stimuli(bit<128> expected_stimuli){
    meta.expected_stimuli = expected_stimuli;
}

table tab_expected_stimuli{
    actions = {
        set_expected_stimuli;
    }
    size = 1;
}

action set_agg_func(bit<32> agg_func){
    meta.agg_func = agg_func;
}

table tab_agg_func{
    actions = {
        set_agg_func;
    }
    size = 1;
}

action set_neuron_bias(bit<WORDSIZE> neuron_1_bias, bit<WORDSIZE> neuron_2_bias){
    meta.neuron_1_bias = neuron_1_bias;
    meta.neuron_2_bias = neuron_2_bias;
}

table tab_neuron_bias{
    actions = {
        set_neuron_bias;
    }
    size = 1;
}

action set_n2n_weight(bit<WORDSIZE> n2n_1_weight_1, bit<WORDSIZE> n2n_1_weight_2, bit<WORDSIZE> n2n_2_weight_1, bit<WORDSIZE> n2n_2_weight_2){
    meta.n2n_1_weight_1 = n2n_1_weight_1;
    meta.n2n_1_weight_2 = n2n_1_weight_2;
    meta.n2n_2_weight_1 = n2n_2_weight_1;
    meta.n2n_2_weight_2 = n2n_2_weight_2;
}

table tab_n2n_weight{
    key = {
        hdr.ann.neuron_id: exact;
    }
    actions = {
        set_n2n_weight;
    }
    size = 256;
}

action set_norm_mean_std(bit<WORDSIZE> neuron_1_mean, bit<WORDSIZE> neuron_2_mean, bit<WORDSIZE> neuron_1_std, bit<WORDSIZE> neuron_2_std){
    meta.neuron_1_mean = neuron_1_mean;
    meta.neuron_2_mean = neuron_2_mean;
    meta.neuron_1_std = neuron_1_std;
    meta.neuron_2_std = neuron_2_std;
}

table tab_norm_mean_std{
    actions = {
        set_norm_mean_std;
    }
    size = 1;
}

action set_activation_func(bit<32> activation_func){
    meta.activation_func = activation_func;
}

table tab_activation_func{
    actions = {
        set_activation_func;
    }
    size = 1;
}

apply {
    if(hdr.ann.isValid()){                                   // If the ANN header is present in the packet
        reg_run_id.read(meta.run_id, 0);
        if(hdr.ann.run_id != meta.run_id){                   // If the run_id in the receiving differs from the stored run_id, reset the received stimuli so we don't mix up data
            reg_run_id.write(0, hdr.ann.run_id);
            reg_received_stimuli.write(0, 0);
            reg_n_received_stimuli.write(0, 0);
        }
        tab_expected_stimuli.apply();                         // Get the bitstring of expected stimuli and store in the MD field
        reg_received_stimuli.read(meta.received_stimuli, 0);  // Get the bitstring of received stimuli and store in the MD field

        // Declare and compute the value of a variable that indicates whether the stimulus in the packet is expected
        bit<128> expected = meta.expected_stimuli & ((bit<128>) 1 << (bit<8>) hdr.ann.neuron_id); // the bit shift and & operator enable us to do the checking.
        // Declare and compute the value of a variable that indicates whether the stimulus in the packet has been received
        bit<128> received = meta.received_stimuli & ((bit<128>) 1 << (bit<8>) hdr.ann.neuron_id);

        // Check if the stimulus is expected and was not yet received
        if((expected > (bit<128>) 0) && (received == (bit<128>) 0)){
            meta.received_stimuli = meta.received_stimuli | ((bit<128>) 1 << (bit<8>) hdr.ann.neuron_id);
            reg_received_stimuli.write(0, meta.received_stimuli);
            // Load n_received_stimuli from register, increment it, and write back
            reg_n_received_stimuli.read(meta.n_received_stimuli, 0);
            meta.n_received_stimuli = meta.n_received_stimuli + 1;
            reg_n_received_stimuli.write(0, meta.n_received_stimuli);
            // Set the register(s) storing the neuron aggregation and bias function
            tab_agg_func.apply();
            tab_neuron_bias.apply();

            //Calculate the aggregation funciton
            if(meta.agg_func == FUNC_NORMALIZATION){
                // normalized_value = (raw_value - weight) / sqrt(biases)
                // since there's no subtraction nor division in P4, must adequate the formula to
                // normalized_value = (raw_value + (-weight)) * (sqrt(bias)) ** -1

                tab_norm_mean_std.apply(); // Load weight (mean) and bias (std)

                // Pass the values to registers to be able to operate them.
                bit<WORDSIZE> operand_a1 = hdr.ann.data_1 << PRECISION;
                bit<WORDSIZE> operand_a2 = hdr.ann.data_2 << PRECISION;					//To load the input data, which are integers, need to shift left to adequate them to FP notation Q.INT.FRAC. TO_DO need special treatment to NEGATIVE INPUT DATA!!!
                bit<WORDSIZE> operand_b1 = meta.neuron_1_mean;
                bit<WORDSIZE> operand_b2 = meta.neuron_2_mean;

                bit<WORDSIZE> sum_result_1 = operand_a1 + operand_b1;                         // compute the sum
                bit<WORDSIZE> sum_result_2 = operand_a2 + operand_b2;
                bit<D_WORDSIZE> sum_result_1_dw = (bit<D_WORDSIZE>) sum_result_1;             // need double to store the multiplication result
                bit<D_WORDSIZE> sum_result_2_dw = (bit<D_WORDSIZE>) sum_result_2;
                // SIGN EXTENSION: When we extend the number of bits of a negative number, we must extend the signal to keep the correctness.
                // Example	-Corect: positive, no need for sign extension	w: 0001 -> dw: 0000 0001
                //			-Corect: negative, with sign extension 			w: 1110 -> dw: 1111 1110
                //			-WRONG:  negative, without sign extension 		w: 1110 -> dw: 0000 1110
                if((sum_result_1_dw & (1 << (WORDSIZE-1))) > 0){                            // negative number
                    sum_result_1_dw = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) sum_result_1_dw;
                }
                if((sum_result_2_dw & (1 << (WORDSIZE-1))) > 0){                            // negative number
                    sum_result_2_dw = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) sum_result_2_dw;
                }
                bit<D_WORDSIZE> operand_c1 = (bit<D_WORDSIZE>) meta.neuron_1_std;
                bit<D_WORDSIZE> operand_c2 = (bit<D_WORDSIZE>) meta.neuron_2_std;
                if((operand_c1 & (1 << (WORDSIZE-1))) > 0){                                // negative number
                    operand_c1 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_c1;
                }
                if((operand_c2 & (1 << (WORDSIZE-1))) > 0){                                // negative number
                    operand_c2 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_c2;
                }
                bit<D_WORDSIZE> norm_result_1 = ((sum_result_1_dw * operand_c1) >> PRECISION);
                bit<D_WORDSIZE> norm_result_2 = ((sum_result_2_dw * operand_c2) >> PRECISION);
                meta.neuron_1_data = (bit<WORDSIZE>) norm_result_1;                           // store the value
                meta.neuron_2_data = (bit<WORDSIZE>) norm_result_2;
                reg_neuron_1_data.write(0, meta.neuron_1_data);
                reg_neuron_2_data.write(0, meta.neuron_2_data);
            }

            else if(meta.agg_func == FUNC_WEIGHTED_SUM){
                // Aggregation Function = weighted sum = bias + Summation_i=1_to_n(data_i * weight_i)
                if(meta.n_received_stimuli == 1){                   		// Check if this is the first stimulus in an ANN run
                    meta.neuron_1_data = meta.neuron_1_bias;            	// If yes, initialize neuron_data with the neuron bias, the neuron bias is added to the accumulator (neuron_data) just once
                    meta.neuron_2_data = meta.neuron_2_bias;
                }
                else{														// If not, read the neuron_data value stored in the register
                    reg_neuron_1_data.read(meta.neuron_1_data, 0);
                    reg_neuron_2_data.read(meta.neuron_2_data, 0);
                }

                tab_n2n_weight.apply();										// Get the neuron weights                
                bit<D_WORDSIZE> operand_a_1_1 = (bit<D_WORDSIZE>) meta.n2n_1_weight_1; 
                bit<D_WORDSIZE> operand_a_1_2 = (bit<D_WORDSIZE>) meta.n2n_1_weight_2;
                bit<D_WORDSIZE> operand_a_2_1 = (bit<D_WORDSIZE>) meta.n2n_2_weight_1;
                bit<D_WORDSIZE> operand_a_2_2 = (bit<D_WORDSIZE>) meta.n2n_2_weight_2;

                bit<D_WORDSIZE> operand_b1 = (bit<D_WORDSIZE>) hdr.ann.data_1;
                bit<D_WORDSIZE> operand_b2 = (bit<D_WORDSIZE>) hdr.ann.data_2;

                // SIGN EXTENSION:
                if((operand_a_1_1 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_a_1_1 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_a_1_1;
                }
                if((operand_a_1_2 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_a_1_2 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_a_1_2;
                }
                if((operand_a_2_1 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_a_2_1 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_a_2_1;
                }
                if((operand_a_2_2 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_a_2_2 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_a_2_2;
                }
                if((operand_b1 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_b1 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_b1;
                }
                if((operand_b2 & (1 << (WORDSIZE-1))) > 0){ // negative number
                    operand_b2 = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_b2;
                }

                bit<D_WORDSIZE> res_1_1 = ((operand_a_1_1 * operand_b1) >> PRECISION);
                bit<D_WORDSIZE> res_1_2 = ((operand_a_1_2 * operand_b2) >> PRECISION);
                bit<D_WORDSIZE> res_2_1 = ((operand_a_2_1 * operand_b1) >> PRECISION);
                bit<D_WORDSIZE> res_2_2 = ((operand_a_2_2 * operand_b2) >> PRECISION);

                meta.neuron_1_data = meta.neuron_1_data + (bit<WORDSIZE>) res_1_1 + (bit<WORDSIZE>) res_1_2;
                meta.neuron_2_data = meta.neuron_2_data + (bit<WORDSIZE>) res_2_1 + (bit<WORDSIZE>) res_2_2;

                reg_neuron_1_data.write(0, meta.neuron_1_data);
                reg_neuron_2_data.write(0, meta.neuron_2_data);
            }

            else if(meta.agg_func == FUNC_IDENTITY){
                meta.neuron_1_data = hdr.ann.data_1;
                meta.neuron_2_data = hdr.ann.data_2;
                reg_neuron_1_data.write(0, meta.neuron_1_data);
                reg_neuron_2_data.write(0, meta.neuron_2_data);
            }

            else if(meta.agg_func == FUNC_ARGMAX){
                // the data to be fowarded (neuron_1_data) is the ID of the neuron with highest value.
                // neuron_2_data is the index of the neuron with highest value inside the same switch.
                // the highest data (neuron_max_value) is kept to be compared by other neurons.
                bit<WORDSIZE> op_a = 0;
                bit<WORDSIZE> op_b = 0;
                bit<1> op_a_sig = 0;
                bit<1> op_b_sig = 0;
                if(meta.n_received_stimuli == 1){
                    // if first stimuli, then assume first data received is the higher, then check the remmaining data against it
                    meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                    meta.neuron_2_data = 0; // neuron_2_data is the index of the neuron with highest value
                    meta.neuron_max_value = hdr.ann.data_1;

                    // Check if data_2 is higher than data_1
                    op_a = hdr.ann.data_2; 			// op_a is the data being evaluated if it's higher then the stored one (op_b)
                    op_b = meta.neuron_max_value;		// op_b is the store of max value until now
                    op_a_sig = (bit<1>)(op_a & (1 << (WORDSIZE-1)) > 0);
                    op_b_sig = (bit<1>)(op_b & (1 << (WORDSIZE-1)) > 0);
                    // There are two situation in which op_a is bigger then op_b
                    if((op_a_sig == 0) && (op_b_sig  == 1)){ // The first: if the op_a is positive and op_b is negative
                        //meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 1;
                        meta.neuron_max_value = hdr.ann.data_2;
                    } else if(op_a_sig == op_b_sig && op_a > op_b){ // The second: if the signal is the same, and op_a > op_b
                        //meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 1;
                        meta.neuron_max_value = hdr.ann.data_2;
                    }
                }
                else{
                    reg_neuron_1_data.read(meta.neuron_1_data, 0); //the index of the neuron with max_data
                    reg_neuron_max_value.read(meta.neuron_max_value, 0);

                    //Run 1st for data_1
                    op_a = hdr.ann.data_1; 			// op_a is the data being evaluated if it's higher then the stored one (op_b)
                    op_b = meta.neuron_max_value;		// op_b is the store of max value until now
                    op_a_sig = (bit<1>)(op_a & (1 << (WORDSIZE-1)) > 0);
                    op_b_sig = (bit<1>)(op_b & (1 << (WORDSIZE-1)) > 0);
                    // There are two situation in which op_a is higher then op_b
                    if((op_a_sig == 0) && (op_b_sig  == 1)){ // The first: if the op_a is positive and op_b is negative
                        meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 0;
                        meta.neuron_max_value = hdr.ann.data_1;
                    } else if(op_a_sig == op_b_sig && op_a > op_b){ // The second: if the signal is the same, and op_a > op_b
                        meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 0;
                        meta.neuron_max_value = hdr.ann.data_1;
                    }

                    //Run 2nd for data_2
                    op_a = hdr.ann.data_2; 			// op_a is the data being evaluated if it's higher then the stored one (op_b)
                    op_b = meta.neuron_max_value;		// op_b is the store of max value until now
                    op_a_sig = (bit<1>)(op_a & (1 << (WORDSIZE-1)) > 0);
                    op_b_sig = (bit<1>)(op_b & (1 << (WORDSIZE-1)) > 0);
                    // There are two situation in which op_a is bigger then op_b
                    if((op_a_sig == 0) && (op_b_sig  == 1)){ // The first: if the op_a is positive and op_b is negative
                        meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 1;
                        meta.neuron_max_value = hdr.ann.data_2;
                    } else if(op_a_sig == op_b_sig && op_a > op_b){ // The second: if the signal is the same, and op_a > op_b
                        meta.neuron_1_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                        meta.neuron_2_data = 1;
                        meta.neuron_max_value = hdr.ann.data_2;
                    }
                }
                reg_neuron_1_data.write(0, meta.neuron_1_data);
                reg_neuron_2_data.write(0, meta.neuron_2_data);
                reg_neuron_max_value.write(0, meta.neuron_max_value);
            }

            tab_n_expected_stimuli.apply();                             // Get the number of expected stimuli for the neuron
            if(meta.n_received_stimuli == meta.n_expected_stimuli){     // Check if the number of expected stimuli was just reached,
                                                                        // If yes, the neuron_data is the final value, we should propagate it
                tab_neuron_id.apply();                                  // Get the neuron ID
                if(meta.neuron_id > 0){
                    hdr.ann.neuron_id = meta.neuron_id;                 // Overwrite the fields in the ANN header
                }

                tab_activation_func.apply();                            // Get the neuron activation function
                if(meta.activation_func == FUNC_RELU){
                    if(meta.neuron_1_data & (1 << (WORDSIZE-1)) > 0){     // Relu: if negative, set data to 0
                        meta.neuron_1_data = 0;
                    }
                    if(meta.neuron_2_data & (1 << (WORDSIZE-1)) > 0){     // Relu: if negative, set data to 0
                        meta.neuron_2_data = 0;
                    }
                    hdr.ann.data_1 = meta.neuron_1_data;                    // Overwrite the fields in the ANN header
                    hdr.ann.data_2 = meta.neuron_2_data;
                }
                else if(meta.activation_func == FUNC_IDENTITY){
                    hdr.ann.data_1 = meta.neuron_1_data;                    // Overwrite the fields in the ANN header
                    hdr.ann.data_2 = meta.neuron_2_data;
                }

                reg_received_stimuli.write(0, 0);                     // Reset the registers related to received stimuli
                reg_n_received_stimuli.write(0, 0);

                ann_forward.apply();                                    // Forward the packet according to the ANN forwarding logic
            } else {
                drop();
            }
        }
    }
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
}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ann);
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
