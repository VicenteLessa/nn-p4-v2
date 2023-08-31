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

    bit<WORDSIZE> neuron_1_data;
    bit<WORDSIZE> neuron_2_data;
    bit<WORDSIZE> neuron_1_argmax;
    bit<WORDSIZE> neuron_2_argmax;
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
    register<bit<WORDSIZE>>(1) reg_neuron_data;
    register<bit<WORDSIZE>>(1) reg_neuron_argmax;
    register<bit<16>>(1) reg_run_id;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mcast(bit<16> mgroup){
        standard_metadata.mcast_grp = mgroup;
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
            if((expected > (bit<128>) 0) && (received == (bit<128>) 0)) {
                meta.received_stimuli = meta.received_stimuli | ((bit<128>) 1 << (bit<8>) hdr.ann.neuron_id);
                reg_received_stimuli.write(0, meta.received_stimuli);

                reg_n_received_stimuli.read(meta.n_received_stimuli, 0);
                meta.n_received_stimuli = meta.n_received_stimuli + 1;
                reg_n_received_stimuli.write(0, meta.n_received_stimuli);


           	 	  tab_agg_func.apply();                                     // Set the register(s) storing the neuron aggregation function
           	 	  tab_neuron_bias.apply();

                if(meta.agg_func == FUNC_WEIGHTED_SUM) {
           	 	 	    if(meta.n_received_stimuli == 1) {                    // Check if this is the first stimulus in an ANN run
           	 	 	 	      meta.neuron_data = meta.neuron_bias;              // If yes, initialize neuron_data with the neuron bias
           	 	 	    }
                    else {
           	 	 	 	      reg_neuron_data.read(meta.neuron_data, 0);        // If not, read the neuron_data value from the register
           	 	 	    }
           	 	 	    tab_n2n_weight.apply();                               // Get the neuron to neuron weight

                    //meta.neuron_data = meta.neuron_data + meta.n2n_weight*hdr.ann.data;
                    bit<D_WORDSIZE> operand_a = (bit<D_WORDSIZE>) meta.n2n_weight;
                    bit<D_WORDSIZE> operand_b = (bit<D_WORDSIZE>) hdr.ann.data;
                    if((operand_a & (1 << (WORDSIZE-1))) > 0){ // negative number
                        operand_a = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_a;
                    }
                    if((operand_b & (1 << (WORDSIZE-1))) > 0){ // negative number
                        operand_b = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_b;
                    }

                    bit<D_WORDSIZE> res = ((operand_a * operand_b) >> PRECISION);
                    meta.neuron_data = meta.neuron_data + (bit<WORDSIZE>) res;
           	 	 	    reg_neuron_data.write(0, meta.neuron_data);

                }else if(meta.agg_func == FUNC_NORMALIZATION) {
                    // normalized_value = (raw_value - weight) / sqrt(biases)
                    // since there's no subtraction nor division in P4, must adequate the formula to
                    // normalized_value = (raw_value + (-weight)) * (sqrt(bias)) ** -1

                    tab_norm_mean_std.apply(); // Load weight (mean) and bias (std)

                    // Pass the values to registers to be able to operate them. To load the input data, which are integers, need to shift left to adequate them to FP notation Q.INT.FRAC.
                    bit<WORDSIZE> operand_a = hdr.ann.data << PRECISION;                      // TO_DO need special treatment to NEGATIVES!!!
                    bit<WORDSIZE> operand_b = meta.norm_mean;
                    bit<WORDSIZE> sum_result = operand_a + operand_b;                         // compute the sum
                    bit<D_WORDSIZE> sum_result_dw = (bit<D_WORDSIZE>) sum_result;             // need double to store the multiplication result
                    if((sum_result_dw & (1 << (WORDSIZE-1))) > 0){                            // negative number
                        sum_result_dw = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) sum_result_dw;
                    }
                    bit<D_WORDSIZE> operand_c = (bit<D_WORDSIZE>) meta.norm_std;              // and then the multiplication
                    if((operand_c & (1 << (WORDSIZE-1))) > 0){                                // negative number
                        operand_c = ((1 << D_WORDSIZE) - (1 << WORDSIZE)) + (bit<D_WORDSIZE>) operand_c;
                    }
                    bit<D_WORDSIZE> norm_result = ((sum_result_dw * operand_c) >> PRECISION);

                    meta.neuron_data = (bit<WORDSIZE>) norm_result;                           // store the value
                    reg_neuron_data.write(0, meta.neuron_data);

                }

                else if(meta.agg_func == FUNC_IDENTITY) {
           	 	 	    meta.neuron_data = hdr.ann.data;
           	 	 	    reg_neuron_data.write(0, meta.neuron_data);
           	 	  }
                
                else if(meta.agg_func == FUNC_ARGMAX) {
                // the data to be fowarded is the index of the neuron with highest value
                // the highest data is kept to be compared by other neurons
           	 	 	    if(meta.n_received_stimuli == 1) {
           	 	 	 	      meta.neuron_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
           	 	 	 	      meta.neuron_argmax = hdr.ann.data;
           	 	 	    }
                    else {
                        /* if(hdr.ann.data > meta.neuron_argmax) {
           	 	 	 	 	        meta.neuron_data = hdr.ann.neuron_id;
           	 	 	 	 	        meta.neuron_argmax = hdr.ann.data;
           	 	 	 	      } */

                        reg_neuron_data.read(meta.neuron_data, 0);
                        reg_neuron_argmax.read(meta.neuron_argmax, 0);

                        bit<WORDSIZE> op_a = hdr.ann.data;
                        bit<WORDSIZE> op_b = meta.neuron_argmax;

                        bit<1> op_a_sig = (bit<1>)(op_a & (1 << (WORDSIZE-1)) > 0);
                        bit<1> op_b_sig = (bit<1>)(op_b & (1 << (WORDSIZE-1)) > 0);
                        if((op_a_sig == 0) && (op_b_sig  == 1)){
                            meta.neuron_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                            meta.neuron_argmax = hdr.ann.data;
                        } else if(op_a_sig == op_b_sig && op_a > op_b){
                            meta.neuron_data = (bit<WORDSIZE>) hdr.ann.neuron_id;
                            meta.neuron_argmax = hdr.ann.data;
                        }
           	 	 	    }
           	 	 	    reg_neuron_data.write(0, meta.neuron_data);
           	 	 	    reg_neuron_argmax.write(0, meta.neuron_argmax);
           	 	  }

                tab_n_expected_stimuli.apply();                             // Get the number of expected stimuli for the neuron
                if(meta.n_received_stimuli == meta.n_expected_stimuli){     // Check if the number of expected stimuli was just reached,
                                                                            // If yes, the neuron_data is the final value, we should propagate it
                    tab_neuron_id.apply();                                  // Get the neuron ID
                    if (meta.neuron_id > 0){
                        hdr.ann.neuron_id = meta.neuron_id;                 // Overwrite the fields in the ANN header
                    }

             	 	 	  tab_activation_func.apply();                            // Get the neuron activation function
             	 	 	  if(meta.activation_func == FUNC_RELU) {
             	 	 	 	    if(meta.neuron_data & (1 << (WORDSIZE-1)) > 0){     // Relu: if negative, set data to 0
             	 	 	 	 	      meta.neuron_data = 0;
             	 	 	 	    }
             	 	 	 	    hdr.ann.data = meta.neuron_data;                    // Overwrite the fields in the ANN header
             	 	 	  }
                    else if(meta.activation_func == FUNC_IDENTITY) {
             	 	 	 	    hdr.ann.data = meta.neuron_data;                    // Overwrite the fields in the ANN header
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
