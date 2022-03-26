# -*- coding: utf-8 -*-
"""
Created on Wed Dec  8 19:02:59 2021

@author: L
"""
# key recovery attack for 82-round katan48
import katan48x48 as ka
from keras.models import model_from_json
from os import urandom
import numpy as np
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "3"#GPU selected for computation

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)
from math import sqrt, log, log2
from time import time


WORD_SIZE = 16;




#Load distinguishers
json_file = open('1099780588546model72.json','r');
json_model = json_file.read();

net50 = model_from_json(json_model);
net50.load_weights('1099780588546best72depth.h5');

json_file1 = open('1099780588546model65.json','r');
json_model1 = json_file1.read();
net43 = model_from_json(json_model1);
net43.load_weights('1099780588546best65depth.h5');


m50 = np.load('data_wrong_key_mean_82r.npy');
s50 = np.load('data_wrong_key_std_82r.npy'); s50 = 1.0/s50;
m43 = np.load('data_wrong_key_mean_75r.npy');
s43 = np.load('data_wrong_key_std_75r.npy'); s43 = 1.0/s43;


def convert_to_binary(l):
  # For KATAN48
  l = l.reshape(-1,48)
  l = l.transpose() 
  #print(len(l))
  X = np.zeros((2304, len(l[0])),dtype=np.uint8);
  for i in range(2304):
    index = i // 48;
    offset = 48 - 1 - i%48;
    X[i] = (l[index] >> offset) & 1;
  X = X.transpose();
  return(X);

#Calculate Hamming weight
def hw(v):
  res = np.zeros(v.shape,dtype=np.uint8);
  for i in range(16):
    res = res + ((v >> i) & 1)
  return(res);

#Hamming weight less than 2 in 0-2**16
low_weight = np.array(range(2**WORD_SIZE), dtype=np.uint16);
low_weight = low_weight[hw(low_weight) <= 2];

'''
plain0 = np.frombuffer(urandom(4),dtype=np.uint32)%pow(2,48);
keys = np.frombuffer(urandom(10),dtype=np.uint16).reshape(5,-1);
keys = np.copy(keys);
keys[1] = np.copy(keys[1]&0xFFBF^0x0040)
p,pb=make_structure(plain0, keys)
print(p,pb)
'''
#generate a katan key, return expanded key
def gen_key(nr):
  keys = np.frombuffer(urandom(10),dtype=np.uint16).reshape(5,-1);
  keys = np.copy(keys);
  myKATAN = ka.KATAN(keys, 48, nr);
  all_key=myKATAN.change_key(keys);
  # 30 bit subkeys consisting of all keys to be recovered
  ks1 = 0x0^(all_key[146]<<15)^(all_key[148]<<14)^(all_key[150]<<13)^(all_key[151]<<12)^(all_key[152]<<11)^(all_key[153]<<10)^(all_key[154]<<9)^(all_key[155]<<8)^(all_key[156]<<7)^(all_key[157]<<6)^(all_key[158]<<5)^(all_key[159]<<4)^(all_key[160]<<3)^(all_key[161]<<2)^(all_key[162]<<1)^(all_key[163]);  
  ks2 = 0x0^(all_key[132]<<15)^(all_key[134]<<14)^(all_key[136]<<13)^(all_key[137]<<12)^(all_key[138]<<11)^(all_key[139]<<10)^(all_key[140]<<9)^(all_key[141]<<8)^(all_key[142]<<7)^(all_key[143]<<6)^(all_key[144]<<5)^(all_key[145]<<4)^(all_key[146]<<3)^(all_key[147]<<2)^(all_key[148]<<1)^(all_key[149]);
  return(keys,ks1,ks2);

def gen_challenge(n, nr, diff=(0x010010080402), keyschedule='real'):
  keys,ks1,ks2 = gen_key(nr);
  cta, ctb = ka.make_structure(n, nr, keys, diff=diff);
  #print(cta[0]^ctb[0])
  return([cta, ctb], ks1, ks2);
'''
cts,ks1,ks2 = gen_challenge(10,83)
#print(cts[0][0:48])#len(cts[0][0])=10,len(cts[0])=48
#cta = np.tile(cts[0][2], 1)
print(cts)
'''
#having a good key candidate, exhaustively explore all keys with hamming distance less than two of this key
def verifier_search(cts, best_guess, use_n = 32, net = net43):
  #print(best_guess);
  #print(cts)
  ck1 = best_guess[0] ^ low_weight;
  ck2 = best_guess[1] ^ low_weight;
  n = len(ck1);#n=137,137 subkeys with Hamming weight below 2
  ck1 = np.repeat(ck1, n*48); keys1 = np.copy(ck1);#137*137
  ck2 = np.repeat(ck2, n*48); keys2 = np.copy(ck2);
  ck1 = np.repeat(ck1, use_n);
  ck2 = np.repeat(ck2, use_n);
  cta = np.tile(cts[0][0:48*use_n], n*n);
  ctb = np.tile(cts[1][0:48*use_n], n*n);
  cta1,ctb1 = ka.dec_rounds1(cta,ctb,ck1)# 7 rounds of decryption using the guessed key
  ctdata = ka.dec_rounds2(cta1,ctb1,ck2)# Decrypt another 10 rounds
  X = convert_to_binary(ctdata);   
  Z = net.predict(X, batch_size=200000);
  Z = Z / (1 - Z);
  Z = np.log2(Z);
  Z = Z.reshape(-1, use_n);
  v = np.mean(Z, axis=1) * use_n;
  m = np.argmax(v); val = v[m];
  key1 = keys1[m]; key2 = keys2[m];
  return(key1, key2, val);
'''
a = np.random.choice(2**(WORD_SIZE));
b = np.random.choice(2**(WORD_SIZE));
best_guess = (a,b)
ct, ks1, ks2 = gen_challenge(10,83);
#print(ct)
verifier_search([ct[0][0], ct[1][0]], best_guess)
'''
#Generate 0~16383, each number has 64
tmp_br = np.arange(2**14, dtype=np.uint16);
tmp_br = np.repeat(tmp_br, 64).reshape(-1,64);



def bayesian_rank_kr(cand, emp_mean, m=m50, s=s50):
  global tmp_br;
  n = len(cand);
  if (tmp_br.shape[1] != n):
      tmp_br = np.arange(2**14, dtype=np.uint16);
      tmp_br = np.repeat(tmp_br, n).reshape(-1,n);
  tmp = tmp_br ^ cand;
  v = (emp_mean - m[tmp]) * s[tmp];
  v = v.reshape(-1, n);
  scores = np.linalg.norm(v, axis=1);
  return(scores);

def bayesian_key_recovery(cts, net=net50, m = m50, s = s50, num_cand = 32, num_iter=5, seed = None):
  n = len(cts[0]);
  keys = np.random.choice(2**(WORD_SIZE-2),num_cand,replace=False); scores = 0; best = 0;
  if (not seed is None):
    keys = np.copy(seed);
  cta, ctb = np.tile(cts[0],num_cand), np.tile(cts[1], num_cand);
  scores = np.zeros(2**(WORD_SIZE-2));
  used = np.zeros(2**(WORD_SIZE-2));
  all_keys = np.zeros(num_cand * num_iter,dtype=np.uint16);
  all_v = np.zeros(num_cand * num_iter);# 160 subkeys
  for i in range(num_iter):
    k = np.repeat(keys, n);
    ctdata = ka.dec_rounds(cta, ctb, k);   
    #print(len(ctdata))
    X = convert_to_binary(ctdata);
    #print(len(X))
    Z = net.predict(X,batch_size=10000);
    Z = Z.reshape(num_cand, -1);
    means = np.mean(Z, axis=1);
    Z = Z/(1-Z); Z = np.log2(Z); v =np.sum(Z, axis=1); all_v[i * num_cand:(i+1)*num_cand] = v;
    all_keys[i * num_cand:(i+1)*num_cand] = np.copy(keys);
    scores = bayesian_rank_kr(keys, means, m=m, s=s);
    tmp = np.argpartition(scores+used, num_cand);
    keys = tmp[0:num_cand];
    r = np.random.randint(0,4,num_cand,dtype=np.uint16); r = r << 14; keys = keys ^ r;
  return(all_keys, scores, all_v);

def bayesian_key_recovery1(cts, net=net50, m = m50, s = s50, num_cand = 32, num_iter=5, seed = None):
  n = len(cts[0]);
  keys = np.random.choice(2**(WORD_SIZE-2),num_cand,replace=False); scores = 0; best = 0;
  if (not seed is None):
    keys = np.copy(seed);
  cta, ctb = np.tile(cts[0],num_cand), np.tile(cts[1], num_cand);
  scores = np.zeros(2**(WORD_SIZE-2));
  used = np.zeros(2**(WORD_SIZE-2));
  all_keys = np.zeros(num_cand * num_iter,dtype=np.uint16);
  all_v = np.zeros(num_cand * num_iter);
  for i in range(num_iter):
    k = np.repeat(keys, n);
    ctdata = ka.dec_rounds2(cta, ctb, k);
    X = convert_to_binary(ctdata);
    Z = net.predict(X,batch_size=10000);
    Z = Z.reshape(num_cand, -1);
    means = np.mean(Z, axis=1);
    Z = Z/(1-Z); Z = np.log2(Z); v =np.sum(Z, axis=1); all_v[i * num_cand:(i+1)*num_cand] = v;
    all_keys[i * num_cand:(i+1)*num_cand] = np.copy(keys);
    scores = bayesian_rank_kr(keys, means, m=m, s=s);
    tmp = np.argpartition(scores+used, num_cand);
    keys = tmp[0:num_cand];
    r = np.random.randint(0,4,num_cand,dtype=np.uint16); r = r << 14; keys = keys ^ r;
  return(all_keys, scores, all_v);
'''
a = np.random.choice(2**(WORD_SIZE));
b = np.random.choice(2**(WORD_SIZE));
best_guess = (a,b)
ct, ks1, ks2 = gen_challenge(10,83);
bayesian_key_recovery([ct[0][0], ct[1][0]])
'''
#core attack 
def test_bayes(cts,it=1, cutoff1=10, cutoff2=10, net=net50, net_help=net43, m_main=m50, m_help=m43, s_main=s50, s_help=s43, verify_breadth=None):
  n = 32;
  if (verify_breadth is None): verify_breadth=64;
  alpha = sqrt(n);
  best_val = -100.0; best_key = (0,0); best_pod = 0; bp = 0; bv = -100.0;
  keys = np.random.choice(2**WORD_SIZE, 64, replace=False);
  eps = 0.001; local_best = np.full(n,-10); num_visits = np.full(n,eps);
  guess_count = np.zeros(2**16,dtype=np.uint16);
  for j in range(it):
      #upper confidence bound
      #selected ciphertext structure
      priority = local_best + alpha * np.sqrt(log2(j+1) / num_visits); i = np.argmax(priority);
      num_visits[i] = num_visits[i] + 1;
      if (best_val > cutoff2):
        return(best_key, j);
      keys, scores, v = bayesian_key_recovery([cts[0][i], cts[1][i]], num_cand=64, num_iter=5,net=net, m=m_main, s=s_main);
      vtmp = np.max(v);
      #print(vtmp)
      if (vtmp > local_best[i]): local_best[i] = vtmp;
      if (vtmp > bv):
        bv = vtmp; bp = i;
      if (vtmp > cutoff1):
        l2 = [i for i in range(len(keys)) if v[i] > cutoff1];
        for i2 in l2:
          cta, ctb = ka.dec_rounds1(cts[0][i],cts[1][i],keys[i2]);        
          keys2,scores2,v2 = bayesian_key_recovery1([cta, ctb],num_cand=64, num_iter=5, m=m43,s=s43,net=net_help);
          vtmp2 = np.max(v2);
          if (vtmp2 > best_val):
            best_val = vtmp2; best_key = (keys[i2], keys2[np.argmax(v2)]); best_pod=i;
            print(vtmp2);
  return(best_key, it);

def test(n, nr=82, num_structures=100, it=500, cutoff1=5.0, cutoff2=50.0, keyschedule='real',net=net50, net_help=net43, m_main=m50, s_main=s50,  m_help=m43, s_help=s43, verify_breadth=None):
  print("Checking KATAN48 implementation."); 
  if (not ka.check_testvector()):
    print("Error. Aborting.");
    return(0);
  arr1 = np.zeros(n, dtype=np.uint16); arr2 = np.zeros(n, dtype=np.uint16); 
  t0 = time();
  data = 0; av=0.0;
  zkey = np.zeros(nr,dtype=np.uint16);
  for i in range(n):
    print("Test:",i);
    # Generate ciphertext structure and key
    ct, ks1, ks2 = gen_challenge(num_structures, nr, keyschedule=keyschedule);
    #Returns the best guess and iteration rounds
    guess, num_used = test_bayes(ct,it=it, cutoff1=cutoff1, cutoff2=cutoff2, net=net, net_help=net_help, m_main=m_main, s_main=s_main, m_help=m_help, s_help=s_help, verify_breadth=verify_breadth);
    #print(guess)
    num_used = min(num_structures, num_used); data = data + 2 * (32*48) * num_used;
    print(data)
    arr1[i] = guess[0] ^ ks1; arr2[i] = guess[1] ^ ks2;
    print("Difference between real key and key guess: ", hex(arr1[i]), hex(arr2[i]));
  t1 = time();
  print("Done.");
  d1 = [hex(x) for x in arr1]; d2 = [hex(x) for x in arr2];
  print("Differences between guessed and last key:", d1);
  print("Differences between guessed and second-to-last key:", d2);
  print("Wall time per attack (average in seconds):", (t1 - t0)/n);
  print("Data blocks used (average, log2): ", log2(data) - log2(n));
  return(arr1, arr2);

arr1, arr2 = test(10);
np.save(open('run_sols1.npy','wb'),arr1);
np.save(open('run_sols2.npy','wb'),arr2);
print('c1=5，c2=50')