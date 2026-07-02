#!/usr/bin/env python3
"""Score CodeQL-PHP against semgrep-rules PHP test annotations (ruleid: = positive, ok: = negative)."""
import csv,sys,os,re
from collections import Counter
def load_expected(sr):
    pos,oks=[],[]
    for dp,_,fs in os.walk(sr):
        for f in fs:
            if not f.endswith('.php'):continue
            rel=os.path.relpath(os.path.join(dp,f),sr)
            for i,l in enumerate(open(os.path.join(dp,f),encoding='utf-8',errors='replace').read().splitlines()):
                if re.search(r'ruleid:',l): pos.append((rel,i+2))
                elif re.search(r'\bok:',l): oks.append((rel,i+2))
    return pos,oks
def load_flagged(csvp):
    s=set()
    for row in csv.reader(open(csvp)):
        if len(row)>=6:
            try:s.add((row[4].lstrip('/'),int(row[5])))
            except:pass
    return s
if __name__=='__main__':
    csvp,sr=sys.argv[1],sys.argv[2]
    pos,oks=load_expected(sr); fl=load_flagged(csvp)
    hit=lambda f,ln:any((f,ln+d) in fl for d in(-1,0,1))
    rp=sum(1 for f,ln in pos if hit(f,ln)); fp=sum(1 for f,ln in oks if hit(f,ln))
    print(f"RECALL {rp}/{len(pos)} ({100*rp//len(pos)}%) | FP-on-ok {fp}/{len(oks)}")
    tot=Counter(f.split('/')[0] for f,_ in pos); h=Counter(f.split('/')[0] for f,ln in pos if hit(f,ln))
    for c in sorted(tot):print(f"  {c}: {h[c]}/{tot[c]}")
