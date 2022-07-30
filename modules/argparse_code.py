import argparse
import os
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("-f", required=True, type=str, help="Pcap file to parse")
args = vars(ap.parse_args())

