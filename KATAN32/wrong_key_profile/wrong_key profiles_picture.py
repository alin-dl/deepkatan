# -*- coding: utf-8 -*-
"""
Created on Fri Dec 31 12:51:44 2021

@author: L
"""

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

a=77   #84
b=77   #84

x_len=pow(2,16)

for i in range(a,b+1):
        filepath1='data_wrong_key_mean_' + str(i+13) + 'r.npy'
        filepath2='data_wrong_key_std_' + str(i+13) + 'r.npy'
        f1=np.load(filepath1)
        f2=np.load(filepath2)
        x=np.arange(x_len)
        
        figsize = 20,11
        plt.subplots(figsize=figsize)
        ax = plt.subplot(1, 1, 1)
        font2 = {'family' : 'Times New Roman',
                 'weight' : 'normal',
                 'size' : 35,
                 }
        plt.xlabel('difference to real key',font2)
        ax.yaxis.set_major_locator(MultipleLocator(0.05))
        ax.xaxis.set_major_locator(MultipleLocator(int(x_len/10)))
        plt.ylim(min(f1[:x_len])-0.002,max(f1[:x_len])+0.002)                      
        plt.xlim(0,x_len)
        #print(x)
        #print(f1[:x_len])
        plt.plot(x, f1[:x_len], color='steelblue', linewidth=2) 
        plt.tick_params(labelsize=23) 

        plt.title(str(i+13)+' Round KATAN32 Mean',fontdict={'family': 'Times New Roman','weight':'normal','size': 30})
        plt.grid()
        #plt.savefig('KATAN48_Mean'+str(i)+'.png', bbox_inches='tight',dpi=500) 
        plt.savefig('KATAN48_Mean'+str(i)+'.png',bbox_inches='tight') 
        
        figsize = 20,11
        plt.subplots(figsize=figsize)
        ax = plt.subplot(1, 1, 1)
        font2 = {'family' : 'Times New Roman',
                 'weight' : 'normal',
                 'size' : 35,
                 }
        plt.xlabel('difference to real key',font2)
        ax.yaxis.set_major_locator(MultipleLocator(0.05))
        ax.xaxis.set_major_locator(MultipleLocator(int(x_len/10)))
        plt.ylim(min(f2[:x_len])-0.002,max(f2[:x_len])+0.002)                      
        plt.xlim(0,x_len)
        plt.plot(x, f2[:x_len], color='indigo', linewidth=2) 
        plt.tick_params(labelsize=23) 

        plt.title(str(i+13)+' Round KATAN32 Std',fontdict={'family': 'Times New Roman','weight':'normal','size': 30})
        plt.grid()
        plt.savefig('KATAN48_Std'+str(i)+'.png',bbox_inches='tight') 