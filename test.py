import time

start_time = []
end_time = []

f1 = open("flow_start.txt",'r')
f2 = open("flow_end.txt",'r')

for i in range (0,185):
    start_time.append(f1.readline())
    end_time.append(f2.readline())
    print(int(end_time[i])-int(start_time[i]))