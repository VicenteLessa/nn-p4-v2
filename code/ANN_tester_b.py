#!/usr/bin/env python
import sys
import socket
import struct
import re
import math
import json
import pandas as pd
import numpy as np
import threading
import queue
from scapy.all import *
'82', '83', '81', '89', '15', '22', '84', '90', '88', '79'

# Creating the config dict in loco, maybe best would be to be in a file
cfg = {
    "input_dataset_filename": "csv_files_input/df_test_1_with_2_attributes.csv",
    "output_csv_filename": "csv_files_output/p4_outputs_classifications_Q16_16_frac_mult.csv",
    "features": [
        {
            "name": "a",
            "iface": "s1-eth1",
            "id": "82"
        }
    ],
    "outputs": [
        {
            "name": "P4_class",
            "iface": "s126-eth2",
            "neuron_id": 126,
            "proc": lambda x: x,
        },
        {
            "name": "output_00",
            "iface": "s126-eth101",
            "neuron_id": 101,
            "proc": lambda x: x/(2**PRECISION) if x < (2**(WORDSIZE - 1)) else (x-(2**WORDSIZE))/(2**PRECISION),
        }
    ]
}
WORDSIZE = 32
PRECISION = 16
SLACK = 8


class ANN(Packet):
    fields_desc = [
        BitField("neuron_id", 0, 32),
        BitField("data_1", 0, WORDSIZE),
        BitField("data_2", 0, WORDSIZE),
        BitField("run_id", 0, 16),
        BitField("slack", 0, SLACK)
    ]

bind_layers(Ether, ANN, type=0x88B5)


def main(cfg):

    # Read input dataset
    input_dataset = pd.read_csv(cfg["input_dataset_filename"]).head(5)

    # Create shared queue and packet sniffer to receive ANN outputs
    packet_queue = queue.Queue()
    output_ifs = [x["iface"] for x in cfg["outputs"]]
    print(output_ifs)
    sniffers = []
    for output_iface in output_ifs:
        sniffers.append(
            AsyncSniffer(iface=output_iface, prn=lambda x: packet_queue.put(x), stop_filter=lambda x: x.haslayer(ANN) and x[ANN].neuron_id == 0)
        )
    for sniffer in sniffers:
        sniffer.start()

    # Run each of the dataset test cases
    ann_outputs = pd.DataFrame(columns=[x["name"] for x in cfg["outputs"]])
    for tc_id, tc in input_dataset.iterrows():
        # Creat input packets
        input_pkts = []
        
        for feat in cfg["features"]:
            input_pkts.append((
                feat["iface"],
                Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr(feat["iface"])) / ANN(neuron_id=0, data_1=tc["82"], data_2=tc["83"], run_id=tc_id)
            ))

        # Send input packets as many times needed to receive all expected outputs
        n_expected_outputs = len(cfg["outputs"])
        n_received_outputs = 0
        received_output = False
        tc_outputs = {}

        while n_received_outputs < n_expected_outputs:
            try:
                # If the queue is empty or this is the first iteration
                if not received_output:
                    # Send input packets
                    for iface, pkt in input_pkts:
                        # print(f"||{iface}|| <<{pkt.show()}>>")
                        sendp(pkt, iface=iface, verbose=False)

                while n_received_outputs < n_expected_outputs:
                    # Try to get an output packet
                    out_pkt = packet_queue.get(timeout=1)

                    # Check if packet is ANN and an output to the current test case
                    if ANN in out_pkt and out_pkt[ANN].run_id == tc_id:
                        for eo in cfg["outputs"]:
                            if eo["neuron_id"] == out_pkt[ANN].neuron_id and eo["name"] not in tc_outputs:
                                received_output = True
                                tc_outputs[eo["name"]] = eo["proc"](out_pkt[ANN].data)
                                n_received_outputs = n_received_outputs + 1
            except queue.Empty as error:
                # If queue was empty, we will send input packet again
                print(error)
                received_output = False
            except Exception as error:
                # An error here is critical
                print(error)

        # Add all desired outputs to the dataframe
        ann_outputs.loc[tc_id] = tc_outputs
        print(end=f"\r{tc_id+1}/{len(input_dataset)}")
    print()

    for sniffer in sniffers:
        sniffer.stop()

    # Write P4 ANN outputs to a file
    ann_outputs.to_csv(cfg["output_csv_filename"])


if __name__ == '__main__':
    main(cfg)
