import os
import time
import multiprocessing
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
logger = logging.getLogger('RansomwareTest')

def cpu_spike():
    start = time.time()
    while time.time() - start < 15:
        for _ in range(1000000):
            pass

target_dir = os.path.expanduser("~/Documents/test")
alt_dir = "/home/kamli/test_files"
os.makedirs(target_dir, exist_ok=True)
os.makedirs(alt_dir, exist_ok=True)

logger.debug("Starting ransomware simulation")
processes = [multiprocessing.Process(target=cpu_spike) for _ in range(multiprocessing.cpu_count())]
for p in processes:
    p.start()
    logger.debug("Started CPU spike process")

for i in range(50):
    file_path = os.path.join(target_dir, f"test{i}.txt")
    with open(file_path, "w") as f:
        f.write("Test file.")
    logger.debug(f"Created file: {file_path}")
    time.sleep(0.03)

for i in range(50):
    old_path = os.path.join(target_dir, f"test{i}.txt")
    new_path = os.path.join(target_dir, f"test{i}.txt.locked")
    os.rename(old_path, new_path)
    logger.debug(f"Renamed {old_path} to {new_path}")
    time.sleep(0.03)

for i in range(3):
    file_path = os.path.join(target_dir, f"READ_ME{i}.txt")
    with open(file_path, "w") as f:
        f.write("Your files are encrypted! Pay to decrypt.")
    logger.debug(f"Created ransom note: {file_path}")
    time.sleep(0.03)

file_path = os.path.join(alt_dir, "READ_ME.txt")
with open(file_path, "w") as f:
    f.write("Your files are encrypted! Pay to decrypt.")
logger.debug(f"Created ransom note: {file_path}")

for p in processes:
    p.join()
logger.debug("Ransomware simulation complete.")
