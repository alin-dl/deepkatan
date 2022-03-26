import katan64x64 as ka

import numpy as np
from time import sleep
from pickle import dump

from keras.callbacks import ModelCheckpoint, LearningRateScheduler
from keras.models import Model
from keras.layers import Dense, Conv1D, Input, Reshape, Permute, Add, Flatten, BatchNormalization, Activation, Dropout
from keras import backend as K
from keras.regularizers import l2

import os
os.environ["CUDA_VISIBLE_DEVICES"] = "3"

import tensorflow as tf
config = tf.compat.v1.ConfigProto(allow_soft_placement=True)
config.gpu_options.allow_growth=True
session = tf.compat.v1.Session(config=config)
tf.compat.v1.keras.backend.set_session(session)

bs = 1000

def cyclic_lr(num_epochs, high_lr, low_lr):
  res = lambda i: low_lr + ((num_epochs-1) - i % num_epochs)/(num_epochs-1) * (high_lr - low_lr)
  return (res)

def make_checkpoint(datei):
  res = ModelCheckpoint(datei, monitor='val_acc', save_best_only = True,verbose=1,mode='max')
  return (res)

#make residual tower of convolutional blocks
def make_resnet(num_blocks=2, num_filters=64, num_outputs=1, d1=64, d2=64, word_size=32, ks=3, reg_param=0.0001, final_activation='sigmoid'):
  #Input and preprocessing layers
  inp = Input(shape=(4096,))
  rs = Reshape((64, 64))(inp)
  conv0 = Conv1D(num_filters, kernel_size=1, padding='same', kernel_regularizer=l2(reg_param))(rs)
  conv0 = BatchNormalization()(conv0)
  conv0 = Activation('relu')(conv0)
  #add residual blocks
  shortcut = conv0
  for i in range(5):
    conv1 = Conv1D(num_filters, kernel_size=ks, padding='same', kernel_regularizer=l2(reg_param))(shortcut)
    conv1 = BatchNormalization()(conv1)
    conv1 = Activation('relu')(conv1)
    #conv1 = Dropout(0.2)(conv1);
    conv2 = Conv1D(num_filters, kernel_size=ks, padding='same',kernel_regularizer=l2(reg_param))(conv1)
    conv2 = BatchNormalization()(conv2)
    conv2 = Activation('relu')(conv2)
    #conv2 = Dropout(0.2)(conv1);
    shortcut = Add()([shortcut, conv2])
  #add prediction head
  flat1 = Flatten()(shortcut);
  dense1 = Dense(d1,kernel_regularizer=l2(reg_param))(flat1);
  dense1 = BatchNormalization()(dense1)
  dense1 = Activation('relu')(dense1)
  dense2 = Dense(d2, kernel_regularizer=l2(reg_param))(dense1)
  dense2 = BatchNormalization()(dense2)
  dense2 = Activation('relu')(dense2)
  out = Dense(num_outputs, activation=final_activation, kernel_regularizer=l2(reg_param))(dense2)
  model = Model(inputs=inp, outputs=out)
  return (model)

def train_katan_distinguisher(num_epochs,Round ,diff):
    #create the network
    net = make_resnet()
    net.compile(optimizer='adam',loss='mse',metrics=['acc'])
    #generate training and validation data
    X, Y = ka.make_train_data(10**6,Round,diff)
    X_eval, Y_eval = ka.make_train_data(10**5, Round,diff)
    #set up model checkpoint
    check = make_checkpoint(str(diff)+'best'+str(Round)+'depth'+'.h5')
    #create learnrate schedule
    lr = LearningRateScheduler(cyclic_lr(10,0.002, 0.0001))
    #train and evaluate
    h = net.fit(X,Y,epochs=num_epochs,batch_size=bs,verbose=1,validation_data=(X_eval, Y_eval), callbacks=[lr,check])
    np.save(str(diff)+'val_acc'+str(Round)+'.npy', h.history['val_acc'])
    np.save(str(diff)+'val_loss'+str(Round)+'.npy', h.history['val_loss'])
    model_json=net.to_json()
    with open(str(diff)+'model'+str(Round)+'.json','w') as file:
        file.write(model_json)
    with open(str(diff)+'History_'+str(Round)+'.txt','wb') as file:        
        dump(h.history,file)
    print("Best validation accuracy: ", np.max(h.history['val_acc']))
    return (max(h.history['val_acc']))

val_acc=train_katan_distinguisher(200, 61, 0x2480482010080400)
