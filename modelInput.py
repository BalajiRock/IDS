
from kafka import KafkaConsumer
from keras import models
import numpy as np # linear algebra
import pandas as pd # 
from pygame import mixer
import pygame

mixer.init()
def convertData(data):
    result = []

    for i in data:

        if i == True:
            i = 1
        elif i == False:
            i = 0    
        i = list(i)
        result.append(i)
    # result = [result]
    return result
# print("not loaded")
model = models.load_model('./model_ssh_ftp.h5')
# model = load_model('./model_ssh_ftp.h5')
# print("loaded")

called  = False
# 	Flow_duration	Inter_arrival_time	Mean_inter_arrival_time	Rev_Flag	CWE_Flag	ECE_Flag	URG_Flag	ACK_Flag	PSH_Flag	RST_Flag	SYN_Flag	FIN_Flag	FTPFlag	SSHFlag	Label
def alert():
    global called
    if called == False:
        called = True
        pygame.mixer.Channel(0).play(pygame.mixer.Sound('./security-alarm-80493.mp3'),-1)

consumer = KafkaConsumer("finalData",bootstrap_servers=['localhost:9092'])
for packet in consumer:
    data = packet.value.decode()
    # data = convertData(data)
    data = data[:-1].split(",")
    # print(data)
    predictions = model.predict(data)
    if(predictions == "SSH-Brute_Force"):
        alert()
        print("SSH-attacked")
    if(predictions == "FTP-Brute-Force"):
        alert()
        print("FTP-attacked")
            

