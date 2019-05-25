def b2v6(bstr):
    # print(bstr)
    segs = []
    i = 0
    while i < len(bstr):
        b1 = bstr[i]
        i += 1
        b2 = bstr[i]
        seg = ""
        if b1:
            seg += hex(b1)[2:4]
            seg += hex(b2)[2:4].rjust(2, '0')
        else:
            seg += hex(b2)[2:4]
        segs.append(seg)
        i += 1

    result = ""
    shortflag = True
    count = 0
    fsegs = []
    for seg in segs:
        if seg == '0':
            if shortflag:
                count += 1
            else:
                fsegs.append(seg)
        else:
            if shortflag:
                if count >= 2:
                    shortflag = False
                    fsegs.append("")
                elif count == 1:
                    fsegs.append("0")
            count = 0
            fsegs.append(seg)

    if shortflag:
        if count >= 2:
            shortflag = False
            fsegs.append("")
        elif count == 1:
                fsegs.append("0")

    result = ":".join(fsegs)

    if result == '':
        result = "::"
        return result

    if result[-1] == ":":
        result += ":"
    elif result[0] == ":" and result[-1] != ":":
        result = ":"+result
    return result

def v62b(sstr):
    segs = sstr.split(":")
    # print(segs)
    if segs[0] == '':
        segs = segs[1:]
    if segs[-1] == '':
        segs = segs[:-1]
    # print(segs)
    num0b = 9 - len(segs)
    result = b''
    for seg in segs:
        if seg == '':
            for i in range(num0b):
                result += int('0', 16).to_bytes(2, "big")
            continue
        result += int(seg, 16).to_bytes(2, "big")
    return result