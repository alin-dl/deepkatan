# -*- coding: utf-8 -*-
"""
Created on Sun Nov 14 20:03:29 2021

@author: deeplearning
"""


from gurobipy import *  
import numpy as np
import math  
import time  

time_start=time.time()#Record start time   
IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)  
r=25  

# Create a new model

m = Model("KATAN64")#Build the KATAN64 MILP model 
# Create variables  
x = m.addVars(64, vtype=gurobipy.GRB.BINARY, name="x")
c = m.addVars(r,6, vtype=gurobipy.GRB.BINARY, name="c") 
s = m.addVars(787,vtype=gurobipy.GRB.BINARY,name="s")
l = m.addVars(800, vtype=gurobipy.GRB.BINARY, name="l")
  
m.update() # update variable environment  

# Set objective  
#sum1=0
#for i in range(r):
#    for j in range(3):
#        sum1 += c[i][j]
#        m.setObjective(sum1, GRB.MINIMIZE) 
m.setObjective(quicksum(c[i,j] for i in range(r) for j in range(6)), GRB.MINIMIZE)
# Add constraint
'''
n = 3*r
m.addConstr(s[n]==0);m.addConstr(s[n+1]==0);m.addConstr(s[n+2]==0);m.addConstr(s[n+3]==0);
m.addConstr(s[n+4]==1);m.addConstr(s[n+5]==0);m.addConstr(s[n+6]==0);m.addConstr(s[n+7]==0);
m.addConstr(s[n+8]==0);m.addConstr(s[n+9]==0);m.addConstr(s[n+10]==0);m.addConstr(s[n+11]==0);
m.addConstr(s[n+12]==0);m.addConstr(s[n+13]==0);m.addConstr(s[n+14]==0);m.addConstr(s[n+15]==0);
m.addConstr(s[n+16]==0);m.addConstr(s[n+17]==0);m.addConstr(s[n+18]==0);m.addConstr(s[n+19]==0);
m.addConstr(s[n+20]==0);m.addConstr(s[n+21]==0);m.addConstr(s[n+22]==0);m.addConstr(s[n+23]==0);
m.addConstr(s[n+24]==0);
m.addConstr(l[n]==0);m.addConstr(l[n+1]==0);m.addConstr(l[n+2]==0);m.addConstr(l[n+3]==0);
m.addConstr(l[n+4]==0);m.addConstr(l[n+5]==0);m.addConstr(l[n+6]==0);m.addConstr(l[n+7]==0);
m.addConstr(l[n+8]==0);m.addConstr(l[n+9]==0);m.addConstr(l[n+10]==0);m.addConstr(l[n+11]==0);
m.addConstr(l[n+12]==0);m.addConstr(l[n+13]==0);m.addConstr(l[n+14]==0);m.addConstr(l[n+15]==0);
m.addConstr(l[n+16]==0);m.addConstr(l[n+17]==0);m.addConstr(l[n+18]==0);m.addConstr(l[n+19]==0);
m.addConstr(l[n+20]==0);m.addConstr(l[n+21]==0);m.addConstr(l[n+22]==0);m.addConstr(l[n+23]==0);
m.addConstr(l[n+24]==0);m.addConstr(l[n+25]==0);m.addConstr(l[n+26]==0);m.addConstr(l[n+27]==0);
m.addConstr(l[n+28]==0);m.addConstr(l[n+29]==0);m.addConstr(l[n+30]==0);m.addConstr(l[n+31]==0);
m.addConstr(l[n+32]==0);m.addConstr(l[n+33]==0);m.addConstr(l[n+34]==0);m.addConstr(l[n+35]==0);
m.addConstr(l[n+36]==0);m.addConstr(l[n+37]==0);m.addConstr(l[n+38]==0);
'''
n = 3*r

m.addConstr(quicksum((s[n+i]) for i in range(25))+quicksum((l[n+j] for j in range(39)))<=1)

for j in range(25):
    m.addConstr(s[j]==x[63-j])
for k in range(39):
    m.addConstr(l[k]==x[38-k])
#KATAN32
'''
flag1=[0,11,6,8,10,15,13]  
flag2=[0,5,4,7,9,19]
flag3=[0,5,4,7,19]
'''
#KATAN48
'''
flag1=[0,9,7,15,13,22,19]  
flag2=[0,6,3,11,12,29]
flag3=[0,6,3,11,29]
'''
#KATAN64
flag1=[0,13,5,17,24,29,25]
flag2=[0,9,4,13,15,39]
flag3=[0,9,4,13,39]
#print(type(flag1[6]))
i=0

for z in range(r):#calculation for r-round 
  
    m.addConstr(-s[i+flag1[6]]-c[z,0]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[z,0]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[i+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[z,0]>=0)
    m.addConstr(-l[i+flag1[4]]+c[z,0]>=0)
    m.addConstr(-l[i+flag1[5]]+c[z,0]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[z,0]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[z,0]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[z,0]>=0)
    # a=1
    if IR[z]==1:
        m.addConstr(-l[i+flag2[5]]-c[z,1]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[z,1]>=0)
        m.addConstr(-s[i+flag2[2]]+c[z,1]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
    # a=0
    if IR[z]==0:
        m.addConstr(-l[i+flag3[4]]-c[z,1]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[z,1]>=0)
        m.addConstr(-s[i+flag3[3]]+c[z,1]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[z,1]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[z,1]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
    #KATAN64 second bit update
    i+=1
    m.addConstr(-s[i+flag1[6]]-c[z,2]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[z,2]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[z+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[z,2]>=0)
    m.addConstr(-l[i+flag1[4]]+c[z,2]>=0)
    m.addConstr(-l[i+flag1[5]]+c[z,2]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[z,2]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[z,2]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[z,2]>=0)
    # a=1
    if IR[z]==1:
        m.addConstr(-l[i+flag2[5]]-c[z,3]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[z,3]>=0)
        m.addConstr(-s[i+flag2[2]]+c[z,3]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
    # a=0
    if IR[z]==0:
        m.addConstr(-l[i+flag3[4]]-c[z,3]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[z,3]>=0)
        m.addConstr(-s[i+flag3[3]]+c[z,3]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[z,3]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[z,3]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
    #KATAN64 third bit update
    i+=1
    m.addConstr(-s[i+flag1[6]]-c[z,4]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[z,4]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[z+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[z,4]>=0)
    m.addConstr(-l[i+flag1[4]]+c[z,4]>=0)
    m.addConstr(-l[i+flag1[5]]+c[z,4]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[z,4]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[z,4]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[z,4]>=0)
    # a=1
    if IR[z]==1:
        m.addConstr(-l[i+flag2[5]]-c[z,5]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[z,5]>=0)
        m.addConstr(-s[i+flag2[2]]+c[z,5]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[z,5]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,5]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,5]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,5]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,5]>=0)
    # a=0
    if IR[z]==0:
        m.addConstr(-l[i+flag3[4]]-c[z,5]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[z,5]>=0)
        m.addConstr(-s[i+flag3[3]]+c[z,5]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[z,5]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[z,5]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[z,5]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
    i+=1
m.addConstr(quicksum(x[j] for j in range(64))>=1)
  
'''
for i in range(32):
    m.addConstr(x[i] >= 0)
'''    
m.Params.LogToConsole=True # Show the solution process   
m.optimize() 

v = m.getVars()
for i in range(32+1150):
    print('%s %g'%(v[i].varName,v[i].x))


#for i in range(r):
#    for j in range(6):
#        print('%s %g'%(c[i,j].varName,c[i,j].x))

cipher = list(range(64))
for i in range(25):
    cipher[i]=int(s[n+i].x)
    print(int(s[n+i].x))
for j in range(39):
    cipher[25+j]=int(l[n+j].x)
    print(int(l[n+j].x))

# the value of the output difference
MASK_VAL = 2 ** 64 - 1;

def rol(x,k):
    return(((x << k) & MASK_VAL) | (x >> (64 - k)));

b=0

for i in range(64):
    b=b^rol(cipher[63-i],i)
print(hex(b))   


#for v in m.getVars():  
#    print('%s %g' % (v.varName, v.x))

print('Obj: %g' % m.objVal)  

time_end=time.time()#Record end time   
print('time cost',time_end-time_start,'s')  



