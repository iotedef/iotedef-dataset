import argparse
import os.path
import sys
import ipaddress
import logging

def split(cname, ipaddr):
    ret = {}
    flow = {}
    lst = []

    logging.info("starting")
    with open(cname, "r") as f:
        for line in f:
            tmp = line.strip().split("|")
            source = tmp[4]
            saddr, sport = source.split(":")
            dest = tmp[5]
            daddr, dport = dest.split(":")

            if (saddr, daddr) in flow:
                flow[(saddr, daddr)] += 1
            else:
                flow[(saddr, daddr)] = 1

    for k in flow:
        lst.append((k, flow[k]))

    lst = sorted(lst, key=lambda x: x[1], reverse=True)

    for (s, d), n in lst:
        sidx = didx = -1
        if s in ret:
            if ret[s] == ipaddr[0]:
                sidx = 0
            else:
                sidx = 1

        if d in ret:
            if ret[d] == ipaddr[0]:
                didx = 0
            else:
                didx = 1

        if sidx < 0 and didx < 0:
            sidx = 0
            didx = 1

        if sidx == didx:
            logging.debug("s: {}, d: {}, n: {}".format(s, d, n))

        if sidx < 0 and didx >= 0:
            sidx = (didx + 1) % 2

        if didx < 0 and sidx >= 0:
            didx = (sidx + 1) % 2

        if s not in ret:
            ret[s] = ipaddr[sidx]

        if d not in ret:
            ret[d] = ipaddr[didx]

    logging.info("finished")

    for k in ret:
        logging.debug("{}: {}".format(k, ret[k]))

    return ret
    
def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--ipaddr0", metavar="<ip address of dev #0>", help="IP address of Dev #0", type=str, required=True)
    parser.add_argument("-b", "--ipaddr1", metavar="<ip address of dev #1>", help="IP address of Dev #1", type=str, required=True)
    parser.add_argument('--csv', metavar='<input csv file>',
                        help='csv file to create', required=True)
    parser.add_argument("-l", "--log", metavar='<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>',
                        help='Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)', type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    logging.basicConfig(level=args.log)
    if not os.path.exists(args.csv):
        logging.error('Output csv file "{}" not exists, '.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    ipaddr = {}
    ipaddr[0] = args.ipaddr0
    ipaddr[1] = args.ipaddr1
    ret = split(args.csv, ipaddr)

    for k in ret:
        print ("{}: {}".format(k, ret[k]))

if __name__ == '__main__':
    main()
