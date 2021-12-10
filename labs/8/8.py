#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Dec  7 09:27:28 2021

@author: gabriel
"""
#%%
import pickle

if __name__ == '__main__':
    with open("bgp20211102.pickle", "rb") as fd:
        graph = pickle.load(fd)
        print(graph.number_of_nodes())
        print(graph.number_of_edges())
        degree_sequence = sorted(graph.degree(),key=lambda x:x[1], reverse =True)
        print([a for a,d in degree_sequence[:5]])
