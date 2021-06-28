of = open("test.label.change", "w")
with open("test.label", "r") as f:
    for line in f:
        tmp = line.strip().split(", ")
        num = int(tmp[0])

        if num >= 1001 and num <= 2000:
            s = "{}, 1\n".format(", ".join(tmp[0:-1]))
            of.write(s)
        else:
            of.write(line)
of.close()
