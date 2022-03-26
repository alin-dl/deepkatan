# -*- coding: utf-8 -*-
"""
Created on Fri Dec 24 16:07:38 2021

@author: L
"""

import katan48x48 as ka
from keras.models import model_from_json
from os import urandom
import numpy as np
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "1"#GPU selected for calculation

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)
import time
start=time.perf_counter()

nr = 82
diff = 0x010010080402
n=3000 

#load distinguishers

json_file = open('1099780588546model72.json','r');
json_model = json_file.read();

net = model_from_json(json_model);
net.load_weights('48_1099780588546best72depth.h5');


def wrong_key_decryption(n, diff, nr, net):
    means = np.zeros(2**16); sig = np.zeros(2**16);
    for i in range(2**16):
        keys=np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
        keys = np.copy(keys);
        myKATAN = ka.KATAN(keys, 48, 254);
        all_key=myKATAN.change_key(keys);
        k_goal = 0x0^(all_key[146]<<15)^(all_key[148]<<14)^(all_key[150]<<13)^(all_key[151]<<12)^(all_key[152]<<11)^(all_key[153]<<10)^(all_key[154]<<9)^(all_key[155]<<8)^(all_key[156]<<7)^(all_key[157]<<6)^(all_key[158]<<5)^(all_key[159]<<4)^(all_key[160]<<3)^(all_key[161]<<2)^(all_key[162]<<1)^(all_key[163]);  
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
     
