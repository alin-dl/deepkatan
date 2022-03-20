# -*- coding: utf-8 -*-
"""
Created on Wed Dec  8 19:02:59 2021

@author: L
"""
#78轮密钥恢复算法
import katan64x64 as ka
from keras.models import model_from_json
from os import urandom
import numpy as np
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "3"#选定进行计算的显卡

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)#设定显卡针对数据量自动分配显存
from math import sqrt, log, log2
from time import time


WORD_SIZE = 16;

#加载区分器
json_file = open('2630181484929483776model61.json','r');
json_model = json_file.read();

net50 = model_from_json(json_model);
net50.load_weights('2630181484929483776best61depth.h5');

json_file1 = open('64r2630181484929483776model54.json','r');
json_model1 = json_file1.read();
net43 = model_from_json(json_model1);
net43.load_weights('64r2630181484929483776best54depth.h5');

                 
m50 = np.load('data_wrong_key_mean_70r.npy');
s50 = np.load('data_wrong_key_std_70r.npy'); s50 = 1.0/s50;
m43 = np.load('data_wrong_key_mean_63r.npy');
s43 = np.load('data_wrong_key_std_63r.npy'); s43 = 1.0/s43;


def convert_to_binary(l):
  #针对KATAN48
  l = l.reshape(-1,64)
  l = l.transpose() 
  #print(len(l))
  X = np.zeros((4096, len(l[0])),dtype=np.uint8);
  for i in range(4096):
    index = i // 64;
    offset = 64 - 1 - i%64;
    X[i] = (l[index] >> offset) & 1;
  X = X.transpose();
  return(X);

#计算汉明重量
def hw(v):
  res = np.zeros(v.shape,dtype=np.uint8);
  for i in range(16):
    res = res + ((v >> i) & 1)
  return(res);

#0-2**16中汉明重量小于2的
low_weight = np.array(range(2**WORD_SIZE), dtype=np.uint16);
low_weight = low_weight[hw(low_weight) <= 2];

#generate a katan key, return expanded key
def gen_key(nr):
  keys = np.frombuffer(urandom(10),dtype=np.uint16).reshape(5,-1);
  keys = np.copy(keys);
  myKATAN = ka.KATAN(keys, 64, nr);
  all_key=myKATAN.change_key(keys);
  #要恢复的所有密钥组成的16bit子密钥
  ks1 = 0x0^(all_key[124]<<15)^(all_key[125]<<14)^(all_key[126]<<13)^(all_key[127]<<12)^(all_key[128]<<11)^(all_key[129]<<10)^(all_key[130]<<9)^(all_key[131]<<8)^(all_key[132]<<7)^(all_key[133]<<6)^(all_key[134]<<5)^(all_key[135]<<4)^(all_key[136]<<3)^(all_key[137]<<2)^(all_key[138]<<1)^(all_key[139]); 
  ks2 = 0x0^(all_key[110]<<15)^(all_key[111]<<14)^(all_key[112]<<13)^(all_key[113]<<12)^(all_key[114]<<11)^(all_key[115]<<10)^(all_key[116]<<9)^(all_key[117]<<8)^(all_key[118]<<7)^(all_key[119]<<6)^(all_key[120]<<5)^(all_key[121]<<4)^(all_key[122]<<3)^(all_key[123]<<2)^(all_key[124]<<1)^(all_key[125]); 
  return(keys,ks1,ks2);

def gen_challenge(n, nr, diff=(0x2480482010080400), keyschedule='real'):
  keys,ks1,ks2 = gen_key(nr);
  cta, ctb = ka.make_structure(n, nr, keys, diff=diff);#cta和ctb的格式为48*n
  #print(cta[0]^ctb[0])
  return([cta, ctb], ks1, ks2);
'''
cts,ks1,ks2 = gen_challenge(10,83)
#print(cts[0][0:48])#len(cts[0][0])=10,len(cts[0])=48
#cta = np.tile(cts[0][2], 1)
print(cts)
'''
#having a good key candidate, exhaustively explore all keys with hamming distance less than two of this key
#验证是否有更好的候选密钥
def verifier_search(cts, best_guess, use_n = 32, net = net43):
  #print(best_guess);
  #print(cts)
  ck1 = best_guess[0] ^ low_weight;
  ck2 = best_guess[1] ^ low_weight;
  n = len(ck1);#n=137,汉明重量低于2的有137个密钥
  ck1 = np.repeat(ck1, n*64); keys1 = np.copy(ck1);#137*137
  ck2 = np.repeat(ck2, n*64); keys2 = np.copy(ck2);
  ck1 = np.repeat(ck1, use_n);
  ck2 = np.repeat(ck2, use_n);
  cta = np.tile(cts[0][0:64*use_n], n*n);#沿x轴复制137*137倍cts[0][0:use_n]是48个密文
  ctb = np.tile(cts[1][0:64*use_n], n*n);
  cta1,ctb1 = ka.dec_rounds1(cta,ctb,ck1)#编写反解函数，解密7轮
  ctdata = ka.dec_rounds2(cta1,ctb1,ck2)#解密10轮并输出差分
  X = convert_to_binary(ctdata);   #问题一解决
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
tmp_br = np.arange(2**14, dtype=np.uint16); #生成0~16383，每个数有32个
tmp_br = np.repeat(tmp_br, 64).reshape(-1,64);


#输入是候选密钥，均值，50轮区分器的错误密钥分布
def bayesian_rank_kr(cand, emp_mean, m=m50, s=s50):
  global tmp_br;
  n = len(cand);
  if (tmp_br.shape[1] != n):
      tmp_br = np.arange(2**14, dtype=np.uint16);
      tmp_br = np.repeat(tmp_br, n).reshape(-1,n);
  tmp = tmp_br ^ cand;
  v = (emp_mean - m[tmp]) * s[tmp];
  v = v.reshape(-1, n);
  scores = np.linalg.norm(v, axis=1);#np.linalg.norm()用于求范数,ord=1：表示求列和的最大值,每一个密钥有32个可能性，将32个反馈值相加，则其值当作反馈值
  return(scores);

#输入是密文，7轮区分器，和错误密钥分布
def bayesian_key_recovery(cts, net=net50, m = m50, s = s50, num_cand = 32, num_iter=5, seed = None):
  n = len(cts[0]);#48
  keys = np.random.choice(2**(WORD_SIZE-2),num_cand,replace=False); scores = 0; best = 0;
  if (not seed is None):
    keys = np.copy(seed);
  cta, ctb = np.tile(cts[0],num_cand), np.tile(cts[1], num_cand);
  scores = np.zeros(2**(WORD_SIZE-2));
  used = np.zeros(2**(WORD_SIZE-2));
  all_keys = np.zeros(num_cand * num_iter,dtype=np.uint16);
  all_v = np.zeros(num_cand * num_iter);#160个密钥
  for i in range(num_iter):
    k = np.repeat(keys, n);#1536长
    ctdata = ka.dec_rounds(cta, ctb, k);   #问题2
    #print(len(ctdata))
    X = convert_to_binary(ctdata);#32长
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
  n = len(cts[0]);#48
  keys = np.random.choice(2**(WORD_SIZE-2),num_cand,replace=False); scores = 0; best = 0;
  if (not seed is None):
    keys = np.copy(seed);
  cta, ctb = np.tile(cts[0],num_cand), np.tile(cts[1], num_cand);
  scores = np.zeros(2**(WORD_SIZE-2));
  used = np.zeros(2**(WORD_SIZE-2));
  all_keys = np.zeros(num_cand * num_iter,dtype=np.uint16);
  all_v = np.zeros(num_cand * num_iter);#160个密钥
  for i in range(num_iter):
    k = np.repeat(keys, n);#1536长
    ctdata = ka.dec_rounds2(cta, ctb, k);   #问题2
    X = convert_to_binary(ctdata);#32长
    Z = net.predict(X,batch_size=10000);
    #print(Z)
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
#core attack 攻击核心
def test_bayes(cts,it=1, cutoff1=10, cutoff2=10, net=net50, net_help=net43, m_main=m50, m_help=m43, s_main=s50, s_help=s43, verify_breadth=None):
  n = 32;#每个结构中由n个明文组成
  if (verify_breadth is None): verify_breadth=64;#每个密文数据由48个密文组成
  alpha = sqrt(n);
  best_val = -100.0; best_key = (0,0); best_pod = 0; bp = 0; bv = -100.0;#bp和bv是best_val和best_key的中间值
  keys = np.random.choice(2**WORD_SIZE, 64, replace=False);
  eps = 0.001; local_best = np.full(n,-10); num_visits = np.full(n,eps);
  guess_count = np.zeros(2**16,dtype=np.uint16);
  for j in range(it):
      #upper confidence bound积极地决定将我们的计算预算花在哪个密文结构上
      #selected ciphertext structure
      priority = local_best + alpha * np.sqrt(log2(j+1) / num_visits); i = np.argmax(priority);
      num_visits[i] = num_visits[i] + 1;
      
      if (best_val > cutoff2):
        '''
        improvement = (verify_breadth > 0);#find_good函数找到满足前加3轮的明文，若不满足则值为0
        while improvement:
          k1, k2, val = verifier_search([cts[0][best_pod], cts[1][best_pod]], best_key, net=net_help, use_n = verify_breadth);
          improvement = (val > best_val);
          if (improvement):
            best_key = (k1, k2); best_val = val;
            #print('mid'+str(best_val))
        '''
        return(best_key, j);
      keys, scores, v = bayesian_key_recovery([cts[0][i], cts[1][i]], num_cand=64, num_iter=5,net=net, m=m_main, s=s_main);
      vtmp = np.max(v);
      #print(vtmp)
      if (vtmp > local_best[i]): local_best[i] = vtmp;
      if (vtmp > bv):
        bv = vtmp; bp = i;
      if (vtmp > cutoff1):
        l2 = [i for i in range(len(keys)) if v[i] > cutoff1];
        #print(1)
        for i2 in l2:
          cta, ctb = ka.dec_rounds1(cts[0][i],cts[1][i],keys[i2]);        
          keys2,scores2,v2 = bayesian_key_recovery1([cta, ctb],num_cand=64, num_iter=5, m=m43,s=s43,net=net_help);
          vtmp2 = np.max(v2);
          #print(2)
          if (vtmp2 > best_val):
            best_val = vtmp2; best_key = (keys[i2], keys2[np.argmax(v2)]); best_pod=i;
            print(vtmp2);
  '''
  improvement = (verify_breadth > 0);
  while improvement:
    k1, k2, val = verifier_search([cts[0][best_pod], cts[1][best_pod]], best_key, net=net_help, use_n = verify_breadth);
    improvement = (val > best_val);
    if (improvement):
      best_key = (k1, k2); best_val = val;
  #print('final:'+str(best_val))
  '''
  return(best_key, it);

def test(n, nr=70, num_structures=100, it=500, cutoff1=0.0, cutoff2=10.0, keyschedule='real',net=net50, net_help=net43, m_main=m50, s_main=s50,  m_help=m43, s_help=s43, verify_breadth=None):
  print("Checking KATAN48 implementation."); #检查Speck算法是否正确
  if (not ka.check_testvector()):
    print("Error. Aborting.");
    return(0);
  arr1 = np.zeros(n, dtype=np.uint16); arr2 = np.zeros(n, dtype=np.uint16); #arr长度为16bitxn
  t0 = time();
  data = 0; av=0.0;
  zkey = np.zeros(nr,dtype=np.uint16);
  for i in range(n):
    print("Test:",i);
    #生成密文结构和密钥
    ct, ks1, ks2 = gen_challenge(num_structures, nr, keyschedule=keyschedule);
    #返回猜测的最好密钥和循环次数
    guess, num_used = test_bayes(ct,it=it, cutoff1=cutoff1, cutoff2=cutoff2, net=net, net_help=net_help, m_main=m_main, s_main=s_main, m_help=m_help, s_help=s_help, verify_breadth=verify_breadth);
    #print(guess)
    num_used = min(num_structures, num_used); data = data + 2 * (64*64) * num_used;
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
print('c1=0，c2=10,it=200，new')