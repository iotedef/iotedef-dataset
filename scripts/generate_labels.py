import argparse
import sys
import os

def init_index():
    ret = {}
    ret["ip.src"] = 4
    ret["ip.dst"] = 5
    ret["tcp.srcport"] = 4
    ret["tcp.dstport"] = 5
    return ret

def check_condition(idx, cond):
    ret = False
    lst = idx.keys()
    for k in lst:
        if k in cond:
            ret = True
    return ret

def parse_condition(idx, cond):
    ret = {}
    conds = cond.strip().split("&&")
    for c in conds:
        tmp = c.split("==")
        ret[tmp[0].strip()] = tmp[1].strip()
    return ret

def extract_packets(fname, conds, idx):
    ret = []
    lst = conds.keys()
    with open(fname, "r") as f:
        for line in f:
            if "bogus" in line:
                continue

#            if "_tcp.local" in line:
#                continue

            try:
                tmp = line.strip().split("|")
                saddr, sport = tmp[4].split(":")
                daddr, dport = tmp[5].split(":")
            except:
                continue
            match = False
            for k in lst:
                if conds[k] in tmp[idx[k]]:
                    ret.append([tmp[0], tmp[1], tmp[2], saddr, sport, daddr, dport, 1])
                    match = True
            if not match:
                ret.append([tmp[0], tmp[1], tmp[2], saddr, sport, daddr, dport, 0])
    return ret

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
    parser.add_argument("-c", "--cond", metavar="<extract rule>",
            help="extract rule")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    idx = init_index()

    if not os.path.exists(args.input):
        print("Input file {} does not exist".format(args.input), file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.output):
        print("Output label file {} already exist".format(args.output), file=sys.stderr)
        sys.exit(-1)

    if not check_condition(idx, args.cond):
        print("Extract rule {} is invalid".format(args.cond), file=sys.stderr)
        sys.exit(-1)

    if args.cond:
        conds = parse_condition(idx, args.cond)
    else:
        conds = {}
    ret = extract_packets(args.input, conds, idx)
    save_file(ret, args.output)

if __name__ == "__main__":
    main()
