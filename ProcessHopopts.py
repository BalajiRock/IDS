import sys
from kafka import KafkaConsumer
import json
from datetime import datetime

consumer = KafkaConsumer("Hopopts",bootstrap_servers=['localhost:9092'])
DestinationPort = 0  
SourcePort = 0
SourceIp = ""
DestinationIP = "" 
Protocol = 0
TimeStamp = ""
Rev_Flag = 0
CWE_Flag = 0
ECE_Flag = 0
URG_Flag = 0
ACK_Flag = 0
PSH_Flag = 0
RST_Flag = 0
SYN_Flag = 0
FIN_Flag = 0
packetLength = 0


def convertTimeFormat(original_time_str):
    old_format = "%b %d, %Y %H:%M:%S.%f"[:22] 
    new_format = "%d/%m/%Y %H:%M:%S.%f"[:22]
    original_time = datetime.strptime(original_time_str[:26], old_format)
    new_time_str = original_time.strftime(new_format)
    return new_time_str

def subtract_time(time1_str, time2_str):

    try:
        time1 = datetime.strptime(time1_str, "%d/%m/%Y %H:%M:%S.%f")
        time2 = datetime.strptime(time2_str, "%d/%m/%Y %H:%M:%S.%f")
        print(time1,time2)
        difference = time1 - time2
        return abs(difference.total_seconds())
    except ValueError:
        # print("Invalid time format.")
        return 0

def initialize():
    global SourcePort
    SourcePort = 0
    global SourceIp
    SourceIp = ""
    global DestinationIP
    DestinationIP = "" 
    global DestinationPort
    DestinationPort = 0   
    global Protocol
    Protocol = 0
    global TimeStamp
    TimeStamp = ""
    global Rev_Flag
    Rev_Flag = 0
    global CWE_Flag
    CWE_Flag = 0
    global ECE_Flag
    ECE_Flag = 0
    global URG_Flag
    URG_Flag = 0
    global ACK_Flag
    ACK_Flag = 0
    global PSH_Flag
    PSH_Flag = 0
    global RST_Flag
    RST_Flag = 0
    global SYN_Flag
    SYN_Flag = 0
    global FIN_Flag
    FIN_Flag = 0
    global packetLength
    packetLength = 0

hashTable = dict()

for packet in consumer:
    data = packet.value.decode()
    lines = data.strip().split("\n")   
    lenOfLines = len(lines)
    initialize()

    for i in range(lenOfLines):
        lines[i] = lines[i].strip()
        if(lines[i].startswith("Destination Port")):
            DestinationPort = int(lines[i].split(":")[1])
        elif(lines[i].startswith("Source Port:")):
            SourcePort = int(lines[i].split(":")[1])
        elif(lines[i].startswith("Source Address:")):
            SourceIp = lines[i].split(":")[1]
        elif(lines[i].startswith("Destination Address:")):
            DestinationIP = lines[i].split(":")[1]
        elif(lines[i].startswith("Arrival Time:")):
            TimeStamp =convertTimeFormat(lines[i].split(":",1)[1][:-3].strip())
        elif(lines[i].startswith("Total Length:")):
            packetLength = int(lines[i].split(":")[1])
        elif(lines[i].startswith("Flags: ")):
            if("Reserved:" in lines[i+1]):
                while(not lines[i].strip().startswith("Window: ")):
                    if("Reserved:" in lines[i] and lines[i].split(":")[1].strip() =="Set"):
                        Rev_Flag = 1   
                    elif ( "Congestion Window Reduced (CWR):" in lines[i] and lines[i].split(":")[1].strip() =="Set"):
                        CWE_Flag = 1  
                    elif ("ECN-Echo:" in lines[i] and lines[i].split(":")[1].strip() =="Set" ):
                        ECE_Flag = 1   
                    elif ("Urgent:" in lines[i] and lines[i].split(":")[1].strip() =="Set"):
                        URG_Flag = 1   
                    elif ("Acknowledgment:" in lines[i] and  lines[i].split(":")[1].strip() =="Set"):
                        ACK_Flag = 1   
                    elif ("Push:" in lines[i] and lines[i].split(":")[1].strip() =="Set") :
                        PSH_Flag = 1   
                    elif ("Reset:" in lines[i] and lines[i].split(":")[1].strip() =="Set") :
                        RST_Flag = 1   
                    elif("Syn:" in lines[i] and lines[i].split(":")[1].strip() =="Set"):
                        SYN_Flag = 1   
                        # print(f"syn bit --->{SourceIp},{DestinationIP},{SourcePort},{DestinationPort}") 
                    elif("Fin:" in lines[i] and lines[i].split(":")[1].strip() =="Set"):
                        FIN_Flag = 1 
                        # print(f"fin bit --->{SourceIp},{DestinationIP},{SourcePort},{DestinationPort}")  
                    i += 1     
    # print("Packet length",packetLength)
    key1 = str(SourceIp+DestinationIP+str(SourcePort)+str(DestinationPort))
    key2 = str(DestinationIP+SourceIp+str(DestinationPort)+str(SourcePort))

    if(key1 not in hashTable.keys() and key2 not in hashTable.keys()):
        value = [1,0,packetLength,0,packetLength,packetLength,0,0,TimeStamp,TimeStamp,0,Rev_Flag,CWE_Flag,ECE_Flag,URG_Flag,ACK_Flag,PSH_Flag,RST_Flag,SYN_Flag,FIN_Flag]
        hashTable[key1] = value
    else:
        if(key1 in hashTable.keys()):
            val = hashTable[key1]
            val[0] +=1
            val[2] += packetLength
            val[4] = max(val[4],packetLength)
            val[5] = min(val[5],packetLength)
            val[10] += subtract_time(TimeStamp,val[9])
            val[9] = TimeStamp
            val[11] += Rev_Flag
            val[12] += CWE_Flag
            val[13] += ECE_Flag
            val[14] += URG_Flag
            val[15] += ACK_Flag
            val[16] += PSH_Flag
            val[17] += RST_Flag
            val[18] += SYN_Flag
            val[19] += FIN_Flag
            
            hashTable[key1] = val
        else:
            val = hashTable[key2]
            val[1] +=1
            val[3] += packetLength
            val[6] = max(val[6],packetLength)
            val[7] = min(val[7],packetLength)
            val[10] += subtract_time(TimeStamp,val[9])
            val[9] = TimeStamp
            val[11] += Rev_Flag
            val[12] += CWE_Flag
            val[13] += ECE_Flag
            val[14] += URG_Flag
            val[15] += ACK_Flag
            val[16] += PSH_Flag
            val[17] += RST_Flag
            val[18] += SYN_Flag
            val[19] += FIN_Flag
            hashTable[key2] = val    



    # print(Rev_Flag,CWE_Flag,ECE_Flag,URG_Flag,ACK_Flag,PSH_Flag,RST_Flag,SYN_Flag,FIN_Flag)
    if FIN_Flag:
        file = open("data.csv","+a")
        print("Source Ip : ",SourceIp)    
        print("Source port : ",SourcePort)    
        print("Destination Ip : ",DestinationIP)
        print("Destination port : ",DestinationPort)  
        print("Protocol : ",Protocol)
        print("Rev_Flag : ",Rev_Flag)
        print("CWE_Flag : ",CWE_Flag)
        print("ECE_Flag : ",ECE_Flag)
        print("URG_Flag : ",URG_Flag)
        print("ACK_Flag : ",ACK_Flag)
        print("PSH_Flag : ",PSH_Flag)
        print("RST_Flag : ",RST_Flag)
        print("SYN_Flag : ",SYN_Flag)
        print("FIN_Flag : ",FIN_Flag)
        if key1 in hashTable.keys():
            values = hashTable[key1]
            if(values[1]!=0):
                bwMean = values[3]/values[1]
            else:
                bwMean = 0
            if(values[0]!=0):        
                fwMean = values[2]/values[0]
            else:
                fwMean = 0    
            print("No of Forward Packets : ",values[0])
            print("No of Backward Packets : ",values[1])
            print("Total Forward Packets Length : ",values[2])
            print("Total Backward Packets Length : ",values[3])
            print("Maximum Forward Packets Length : ",values[4])
            print("Minimum Forward Packets Length : ",values[5])
            print("Maximum Backward Packets Length : ",values[6])
            print("Minimum Backward Packets Length : ",values[7])
            print("Mean Forward Packets Length : ",fwMean)
            print("Mean Backward Packets Length : ",bwMean)
            print("Flow Duration : ",subtract_time(values[8],TimeStamp))
            print("Inter Arrival Time : ",values[10])
            print("Mean Inter Arrival Time : ",values[10]/(values[0]+values[1]))
            file.write(f"{TimeStamp},{SourceIp},{DestinationIP},{SourcePort},{DestinationPort},{Protocol},{values[0]},{values[1]},{values[2]},{values[3]},{values[4]},{values[5]},{values[6]},{values[7]},{fwMean},{bwMean},{subtract_time(values[8],TimeStamp)},{values[10]},{values[10]/(values[0]+values[1])},{values[11]},{values[12]},{values[13]},{values[14]},{values[15]},{values[16]},{values[17]},{values[18]},{values[19]},Benign\n")

            hashTable.pop(key1)
        else:
            values = hashTable[key2]
            if(values[1]!=0):
                fwMean = values[3]/values[1]
            else:
                fwMean = 0
            if(values[0]!=0):        
                bwMean = values[2]/values[0]
            else:
                bwMean = 0    
            # print(f"{DestinationPort},{values},{fwMean},{bwMean}")

            print("No of Forward Packets : ",values[0])
            print("No of Backward Packets : ",values[1])
            print("Total Forward Packets Length : ",values[2])
            print("Total Backward Packets Length : ",values[3])
            print("Maximum Forward Packets Length : ",values[4])
            print("Minimum Forward Packets Length : ",values[5])
            print("Maximum Backward Packets Length : ",values[6])
            print("Minimum Backward Packets Length : ",values[7])
            print("Mean Forward Packets Length : ",fwMean)
            print("Mean Backward Packets Length : ",bwMean)
            print("Flow Duration : ",subtract_time(values[8],TimeStamp))
            print("Inter Arrival Time : ",values[10])
            print("Mean Inter Arrival Time : ",values[10]/(values[0]+values[1]))
            file.write(f"{TimeStamp},{SourceIp},{DestinationIP},{SourcePort},{DestinationPort},{Protocol},{values[0]},{values[1]},{values[2]},{values[3]},{values[4]},{values[5]},{values[6]},{values[7]},{fwMean},{bwMean},{subtract_time(values[8],TimeStamp)},{values[10]},{values[10]/(values[0]+values[1])},{values[11]},{values[12]},{values[13]},{values[14]},{values[15]},{values[16]},{values[17]},{values[18]},{values[19]},Benign\n")

            hashTable.pop(key2)  
        print("\n\n")