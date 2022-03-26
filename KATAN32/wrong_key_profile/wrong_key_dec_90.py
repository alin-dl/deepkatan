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
os.environ["CUDA_VISIBLE_DEVICES"] = "3"#GPU selected for calculation

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)
import time
start=time.perf_counter()

nr = 90
diff = 0x61082200
n=3000 

#load distinguishers

json_file = open('1627922944model77.json','r');
json_model = json_file.read();

net = model_from_json(json_model);
net.load_weights('1627922944best77depth.h5');


def wrong_key_decryption(n, diff, nr, net):
    means = np.zeros(2**16); sig = np.zeros(2**16);
    for i in range(2**16):
        keys=np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
        keys = np.copy(keys);
        myKATAN = ka.KATAN(keys, 32, 254);
        all_key=myKATAN.change_key(keys);
        k_goal = 0x0^(all_key[162]<<15)^(all_key[164]<<14)^(all_key[166]<<13)^(all_key[167]<<12)^(all_key[168]<<11)^(all_key[169]<<10)^(all_key[170]<<9)^(all_key[171]<<8)^(all_key[172]<<7)^(all_key[173]<<6)^(all_key[174]<<5)^(all_key[175]<<4)^(all_key[176]<<3)^(all_key[177]<<2)^(all_key[178]<<1)^(all_key[179]);
        k = i ^ k_goal
        X = ka.make_recover_data2(n, nr, diff, keys, k)
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
     
