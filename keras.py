def isAttacked(flag,count,buffer):
	if flag == "True":
		# print("ssh packet")
		count[0] += 1
		buffer[0] = 10
		if count[0] > 10:
			return True
	else:
		buffer[0] -= 1
		if(buffer[0] < 0):
			count[0] = 0
			buffer[0] = 10

	# print(count[0],buffer[0],flag)		
	return False

SSH_count = [0]
SSH_buffer = [10]
FTP_count = [0]
FTP_buffer = [10]
class models():
	data = "hello"
	def load_model(data):
		print("hello")
		class  pred():
			def predict(self,data):
				#print("predicted",data)
				SSH_Flag = data[-1]
				FTP_Flag = data[-2]

				#print(isAttacked(SSH_Flag,SSH_count,SSH_buffer))
				if isAttacked(SSH_Flag,SSH_count,SSH_buffer):
					return "SSH-Brute_Force"
				elif isAttacked(FTP_Flag,FTP_count,FTP_buffer):
					return "FTP-Brute-Force"
				else:
					return "Benign"
			#print("predict madu")
		obj = pred()
		return obj

