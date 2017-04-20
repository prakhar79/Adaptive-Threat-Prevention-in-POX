import os
import threading
import time
import random

hostIP = "10.0.0.5"

while(1):
	randTime = random.randint(1,5)
	os.system("iperf -c %s -t %s" % (hostIP,randTime))
	time.sleep(random.randint(1,5))