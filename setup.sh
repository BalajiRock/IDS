sudo systemctl start kafka.service
sudo systemctl start zookeeper.service
sudo tshark -i enp0s3 -V | python3 loadDataInKafka.py
