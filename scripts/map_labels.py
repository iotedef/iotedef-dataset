import argparse
import sys
import os

def load_mapping(mapping):
    ret = {}
    with open(mapping, "r") as f:
        for line in f:
            tmp = line.strip().split(", ")
            ret[tmp[0]] = tmp[1]
    return ret

def mapping(fname, ofname, maps):
    of = open(ofname, "w")
    with open(fname, "r") as f:
        for line in f:
            tmp = line.strip().split(", ")
            key1 = "{}:{}".format(tmp[3], tmp[4])
            key2 = "{}:{}".format(tmp[5], tmp[6])
            addr1, port1 = maps[key1].split(":")
            addr2, port2 = maps[key2].split(":")
            s = "{}, {}, {}, {}, {}, {}, {}, {}\n".format(tmp[0], tmp[1], tmp[2], addr1, port1, addr2, port2, tmp[-1])
            of.write(s)
    of.close()

def save_file(pkts, ofname):
    with open(ofname, "w") as of:
        for [num, seconds, protocol, saddr, sport, daddr, dport, label] in pkts:
            of.write("{}, {}, {}, {}, {}, {}, {}, {}\n".format(num, seconds, protocol, saddr, sport, daddr, dport, label))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", metavar="<input csv file>",
            help="csv file to parse", required=True)
    parser.add_argument("-o", "--output", metavar="<output file name>",
            help="output file name", required=True)
    parser.add_argument("-m", "--mapping", metavar="<mapping file name>",
            help="mapping file name", required=True)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    if not os.path.exists(args.input):
        print("Input file {} does not exist".format(args.input), file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.output):
        print("Output label file {} already exist".format(args.output), file=sys.stderr)
        sys.exit(-1)

    maps = load_mapping(args.mapping)
    mapping(args.input, args.output, maps)

if __name__ == "__main__":
    main()
