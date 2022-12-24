from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs
import time
puf = XORArbiterPUF(n=64, k=8, seed=1, noisiness=.05)

start = time.time()
puf.eval(random_inputs(n=64, N=128, seed=2))
stop = time.time()
print(stop-start)