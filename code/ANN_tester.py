#!/usr/bin/env python
import sys
import socket
import struct
import re
import math
import json
import pandas as pd
import numpy as np

from scapy.all import *
from ANN_hdrs import *

def main():

    if1 = 's1-eth1'
    if2 = 's2-eth1'
    if3 = 's126-eth2'
    csv_path = "csv_files_input/TF_Predictions_with_Q16dot16.csv"
    df = pd.read_csv(csv_path)
    #df.pop('index')
    #df.rename(columns={"83": "min_seg", "82": "max_seg"})
    print(df)
    p4_predictions = []

    for index, row in df.iterrows():

        attr1_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr(if1)) / \
                    ann(neuron_id = 0, data = row["83"], run_id = index)

        attr2_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr(if2)) / \
                    ann(neuron_id = 0, data = row["82"], run_id
                     = index)

        received_response = False

        while not received_response:
            try:
                sendp(attr1_pkt, iface=if1, verbose=False)
                sendp(attr2_pkt, iface=if2, verbose=False)
                resp_pkt = sniff(iface = if3, count = 1, timeout = 1)[0]

                if ann in resp_pkt:
                    received_response = True
                    print(end=f"\r{resp_pkt[ann].__repr__()} ")
                    p4_predictions.append(resp_pkt[ann].__repr__()[1] - 101)

            except Exception as error:
                #print(error)
                pass

        print(end=f"{index+1}/{len(df)}")

    #print(p4_predictions)
    df=df
    df.insert(loc = 4, column = "p4_predictions", value = p4_predictions)
    print("\n",df)
    #df.hist()

    p4_vs_real_hits = 0
    p4_vs_real_accuracy = 0
    p4_vs_tf_hits = 0
    p4_vs_tf_accuracy = 0
    tf_vs_real_hits = 0
    tf_vs_real_accuracy = 0

    for index, row in df.iterrows():
        if row["real_classes"] == row["tf_predictions"]:
            tf_vs_real_hits = tf_vs_real_hits + 1
        if row["real_classes"] == row["p4_predictions"]:
            p4_vs_real_hits = p4_vs_real_hits + 1
        if row["tf_predictions"] == row["p4_predictions"]:
            p4_vs_tf_hits = p4_vs_tf_hits + 1
        else:
            tf = row["tf_predictions"]
            p4 = row["p4_predictions"]
            print(f"miss:{index}, tf:{tf}, p4:{p4}")



    p4_vs_real_accuracy = p4_vs_real_hits / df.shape[0]
    p4_vs_tf_accuracy = p4_vs_tf_hits / df.shape[0]
    tf_vs_real_accuracy = tf_vs_real_hits / df.shape[0]
    print("p4_vs_real_hits: ", p4_vs_real_hits, "p4_vs_real_accuracy: ", p4_vs_real_accuracy)
    print("p4_vs_tf_hits: ", p4_vs_tf_hits, "p4_vs_tf_accuracy: ", p4_vs_tf_accuracy)
    print("tf_vs_real_hits: ",tf_vs_real_hits, "tf_vs_real_accuracy: ", tf_vs_real_accuracy)

    df.to_csv("csv_files_output/Output_Classifications_Q16_16.csv")


if __name__ == '__main__':
    main()
