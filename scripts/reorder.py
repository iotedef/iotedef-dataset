import argparse
import os
import subprocess
import sys

def reorder(fname):
    ret = []
    with open(fname, "r") as f:
        for line in f:
            tmp = line.strip().split(", ")
            ts = float(tmp[1])
            key = "{}:{}-{}:{}".format(tmp[3], tmp[4], tmp[5], tmp[6])
            ret.append((ts, key, tmp[1:]))

    ret = sorted(ret, key=lambda x: x[0])
    return ret

def timestamp_to_num(cname):
    ret = {}
    with open(cname, "r") as f:
        for line in f:
            tmp = line.strip().split("|")
            num = int(tmp[0])
            ts = float(tmp[1])
            key = "{}-{}".format(tmp[4], tmp[5])

            if ts not in ret:
                ret[ts] = {}

            if key not in ret[ts]:
                ret[ts][key] = []

            ret[ts][key].append(num)
    return ret

def write_to_file(ofname, maps, labels):
    result = []
    for ts, key, l in labels:
        new_number = maps[ts][key].pop(0)
        result.append((new_number, "{}, {}".format(new_number, ', '.join(l))))
    result = sorted(result, key=lambda x: x[0])

    num = 0
    with open(ofname, "w") as of:
        for _, l in result:
            num += 1
            of.write("{}\n".format(l))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', metavar='<input label file>',
                        help='Input label file', required=True)
    parser.add_argument('--csv', metavar='<input csv file>',
                        help='Input csv file', required=True)
    parser.add_argument('--output', metavar='<output label file>',
                        help='Output label file', required=True)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    if not os.path.exists(args.label):
        print('Input label file "{}" does not exist'.format(args.label),
              file=sys.stderr)
        sys.exit(-1)

    if not os.path.exists(args.csv):
        print('Input label file "{}" does not exist'.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.output):
        print('Output csv file "{}" exist'.format(args.output),
              file=sys.stderr)
        sys.exit(-1)

    labels = reorder(args.label)
    maps = timestamp_to_num(args.csv)
    write_to_file(args.output, maps, labels)

if __name__ == '__main__':
    main()
