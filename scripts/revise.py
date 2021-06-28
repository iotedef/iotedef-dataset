import argparse
import os
import sys
import pcap2csv
import analysis
import rewrite
import time

def load_mapping(mname):
    ret = {}
    with open(mname, "r") as f:
        for line in f:
            tmp = line.strip().split(", ")
            ret[tmp[0]] = tmp[1]
    return ret

def revise(pcap, mapping):
    name = pcap.split(".")[0]
    cname = "{}.csv".format(name)

    pcap2csv.pcap2csv(pcap, cname)

    if not mapping:
        mapping = analysis.analysis(cname)

    rewrite.rewrite(pcap, mapping)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('-m', '--mapping', metavar='<mapping file>',
            help='mapping file', default=None)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    mname = args.mapping

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if mname and os.path.exists(mnam):
        mapping = load_mapping(mname)
    else:
        mapping = None

    revise(args.pcap, mapping)

if __name__ == '__main__':
    main()
