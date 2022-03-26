# -*- coding: utf-8 -*-
"""
Created on Fri Dec 24 16:07:38 2021

@author: L
"""

import katan32x32 as ka
from keras.models import model_from_json
from os import urandom
import numpy as np
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "2"#GPU selected for calculation

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)
import time
start=time.perf_counter()

nr = 97
diff = 0x61082200
n=3000 

#load distinguishers

json_file = open('1627922944model84.json','r');
json_model = json_file.read();

net = model_from_json(json_model);
net.load_weights('1627922944best84depth.h5');


def wrong_key_decryption(n, diff, nr, net):
    means = np.zeros(2**16); sig = np.zeros(2**16);
    for i in range(2**16):
        keys=np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
        keys = np.copy(keys);
        myKATAN = ka.KATAN(keys, 32, 254);
        all_key=myKATAN.change_key(keys);
        k_goal = 0x0^(all_key[176]<<15)^(all_key[178]<<14)^(all_key[180]<<13)^(all_key[181]<<12)^(all_key[182]<<11)^(all_key[183]<<10)^(all_key[184]<<9)^(all_key[185]<<8)^(all_key[186]<<7)^(all_key[187]<<6)^(all_key[188]<<5)^(all_key[189]<<4)^(all_key[190]<<3)^(all_key[191]<<2)^(all_key[192]<<1)^(all_key[193]);  
        k = i ^ k_goal
        X = ka.make_recover_data1(n, nr, diff, keys, k)
        Z = net.predict(X,batch_size=10000)
        Z = Z.flatten();
        means[i] = np.mean(Z);
        sig[i] = np.std(Z);
    return(means, sig);

means, sig = wrong_key_decryption(n, diff, nr, net)
#print(means)
np.save('data_wrong_key_mean_'+str(nr)+'r.npy', means)
np.save('data_wrong_key_std_'+str(nr)+'r.npy', sig)

end=time.perf_counter()   
print((end-start),'s')            
     
