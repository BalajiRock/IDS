'usr/bin/python3'
import sys
from kafka import KafkaProducer
data = ""
hash = dict()
protocols = set()
l = []
count = 0
producer = KafkaProducer(bootstrap_servers='localhost:9092')

for line in sys.stdin:
    if(line.startswith("Frame ")) :
        count += 1
        try:
            protocol = hash["[Protocols in frame"].split(":",2)[-1][:-1]
            protocols.add(protocol)
            if("udp" in protocol):
                producer.send("Udp",bytes(str(data), 'utf-8'))
            elif("tcp" in protocol):    
                producer.send("Tcp",bytes(str(data), 'utf-8'))
            elif("Hopopts" in protocol):
                producer.send("Hopopts",bytes(str(data), 'utf-8'))

        except:
            # print("error")
            pass
        data = ""
        count = 0 
        hash = dict()
        data += line
        try:
            key,value = line.strip().split(":",1)
            hash[key] = value
        except:
            l.append(line)   
    else:
        count+=1
        data += line
        try:
            key,value = line.strip().split(":",1)
            hash[key] = value
        except:
            l.append(line)    
    producer.flush()        
# print(data)  
print(protocols)                  
