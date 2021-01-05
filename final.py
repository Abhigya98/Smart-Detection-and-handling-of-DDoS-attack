import pandas as pd
import csv
import subprocess


df = pd.read_csv('clean_all_flood.csv')
t0=0.000000
t1=4.000000
z=0
iteration=df['No.'].values[0]
iteration2=df['No.'].values[len(df)-1]
iteration1=iteration


while(True):
  print("\n\n")
  packets=df[(df.Time >= t0) & (df.Time <= t1)]

  print("t0= ", t0, "t1= ",t1)
    
  lines=len(packets)
  if(lines > 2000):
    #different types of TCP floodings
    countSYNACK = 0
    countSYN = 0
    countACK = 0
    countRST = 0
    countPSH = 0
    countPSHACK = 0
    countRSTACK = 0
    countSYNRST = 0
    countSYNPSH = 0
    countSYNPSHACK = 0
    countAllFlags = 0
    countFin = 0
    countURG = 0
    countURGACK = 0

    Source_IP = df[df.columns[3]]
    print("\n")
    Source_IP = set(list(Source_IP))
    print(Source_IP)
    with open('C:/Windows/System32/blockit.txt','a') as f:
      for i in Source_IP:
        f.write(i)
        f.write('\n')
    f.close()
    indv_count = {'SYN' : 0, 'ACK' : 0, 'RST' : 0, 'PSH' : 0, 'FIN' : 0, 'URG' : 0}

    #reading info column values
    Info = packets['Info'].values

    #segregating flags for info column
    for x in Info:
      if x.find("[SYN, ACK]") != -1:
        countSYNACK = countSYNACK +1
 
    for x in Info:
      if x.find("[SYN]") != -1:
        countSYN = countSYN +1

    for x in Info:
      if x.find("[FIN]") != -1:
        countFIN = countFIN +1

    for x in Info:
      if x.find("[URG]") != -1:
        countURG = countURG +1   

    for x in Info:
      if x.find("[URG, ACK]") != -1:
        countURGACK = countURGACK +1      
 
    for x in Info:
      if x.find("[ACK]") != -1:
        countACK = countACK +1
 
    for x in Info:
      if x.find("[RST]") != -1:
        countRST = countRST +1
    
    for x in Info:
      if x.find("[RST, ACK]") != -1:
        countRSTACK = countRSTACK +1

    for x in Info:
      if x.find("[PSH, ACK]") != -1:
        countPSHACK = countPSHACK +1 

    for x in Info:
      if x.find("[PSH]") != -1:
        countPSH = countPSH +1

    for x in Info:
      if x.find("[SYN, RST]") != -1:
        countSYNRST = countSYNRST +1

    for x in Info:
      if x.find("[SYN, PSH]") != -1:
        countSYNPSH = countSYNPSH +1 

    for x in Info:
      if x.find("[SYN, PSH, ACK]") != -1:
        countSYNPSHACK = countSYNPSHACK +1

    for x in Info:
      if x.find("[FIN, SYN, RST, PSH, ACK, URG]") != -1:
        countAllFlags = countAllFlags +1 

    #Combination Counts 

    info = packets['Info']
    count = {}
    flags = []
    for i in info:
        if i[0] == '[':
          i = i[i.index(']') + 1 :]
        if '[TCP ACKed unseen segment]' in i:
          i = i[i.index(']') + 1 :]
        start = i.index('[')
        end = i.index(']') + 1
        flags.append(i[start : end])
    unique_flags = list(pd.unique(flags))
    for i in unique_flags:
        count.update( {i : flags.count(i)} )

    indv_count = {'SYN' : 0, 'ACK' : 0, 'RST' : 0, 'PSH' : 0, 'FIN' : 0, 'URG' : 0}
    for i in indv_count:
        for j in count:
            if len(j) == 5:
                continue
            if len(j) == 10 and 'ACK' in j:
                continue
            if i in j:
                indv_count[i] += count[j]
    indv_count_list = []
    for i in indv_count:
        indv_count_list.append(indv_count[i])

    #total count of flags and putting in csv file
    countSYN = countSYN + indv_count_list[0]
    countACK = countACK + indv_count_list[1]
    countRST = countRST + indv_count_list[2]
    countPSH = countPSH + indv_count_list[3]
    countFin = countFin + indv_count_list[4]
    countURG = countURG + indv_count_list[5]

    #Putting flag count in the csv file
    with open('FlagCount.csv', 'w', newline='') as file1:
      writer = csv.writer(file1)
      writer.writerow([ "FlagName", "FlagCount"])
      writer.writerow([ "[SYN]", countSYN])
      writer.writerow([ "[SYN,ACK]", countSYNACK])
      writer.writerow([ "[ACK]", countACK])
      writer.writerow([ "[RST]", countRST])
      writer.writerow([ "[RST,ACK]", countRSTACK])
      writer.writerow([ "[PSH]", countPSH]) 
      writer.writerow([ "[PSH,ACK]", countPSHACK])
      writer.writerow([ "[SYN,RST]", countSYNRST])
      writer.writerow([ "[SYN,PSH]", countSYNPSH])   
      writer.writerow([ "[SYN,PSH,ACK]", countSYNPSHACK])
      writer.writerow([ "[FIN,SYN,RST,PSH,ACK,URG]", countAllFlags])
      writer.writerow([ "[URG]", countURG])
      writer.writerow([ "[URG, ACK]", countURGACK])
      writer.writerow([ "[FIN]", countFin]) 

    #Category of attack
    if countSYN != countSYNACK:
      print('SYN Flooding/SYN-ACK Flooding')
    

    if countRST != countRSTACK:
      print('RST Flooding/RST-ACK Flooding')

    if countPSH != countPSHACK:
      print('PSH Flooding/PSHACK Flooding')

    if countURG != countURGACK:
      print('URG Flooding/URGACK Flooding')

    if countFin % 2 != 0:
      print('FIN Flooding')   
    
    df1 = pd.read_csv('FlagCount.csv') 
    print(df1)
    subprocess.call([r'C:\Windows\System32\blockit.bat'], shell =True)
    print("\n IP blocked \n")    

    f=open('C:/Windows/System32/blockit.txt','a')
    f.truncate(0)
    
  else:
      print("No ddos")

  if((iteration>=(iteration2))):
      print("break")
      break      
  #print("length= ",lines)
  iteration=(df['No.'].values[z+lines]+1)
  #print("iteration= ",iteration)
  z=z+lines


  iteration1=iteration
  #print("i= ",z)
  t0=t0+4
  t1=t1+4
  
  
print("\n\n\n Out of while loop \n\n\n")

