import tensorflow as tf
# from tensorflow.python import keras
# from keras.models import load_model
# # import keras_models

import numpy as np # linear algebra
import pandas as pd # 

from sklearn import *
result = []

data = [21,	56266,6,9,15,588,976,79,52,86,0,65.06666667,65.33333333,8.206,8.206,0.341916667,0,0,0,0,23,13,0,2,1,1,0]
# data=[47360,22,6,1,0,52,0,52,52,0,0,52,0,0,0,0,0,0,0,0,1,0,0,0,1,0,1] ssh
# data = [49664,443,17,1,1,0,0,0,0,0,0,0,0,1.6033,1.6033,0.80165,0,0,0,0,0,0,0,0,0,0,0]
for i in data:
    i = list([list([i])])
    result.append(i)

result = [result]
print(result)

# model = load_model('./model_ssh_ftp.h5')
# predictions = model.predict(result)

# print(predictions)

# 	Flow_duration	Inter_arrival_time	Mean_inter_arrival_time	Rev_Flag	CWE_Flag	ECE_Flag	URG_Flag	ACK_Flag	PSH_Flag	RST_Flag	SYN_Flag	FIN_Flag	FTPFlag	SSHFlag	Label
