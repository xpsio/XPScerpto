#!/usr/bin/env python3
import sys,re,pathlib
mds=[]
root=pathlib.Path(sys.argv[1])
for p in root.rglob('*.md'):
  t=p.read_text(encoding='utf-8')
  heads=[]
  for line in t.splitlines():
    m=re.match(r'^(#{2,6})\s+(.+)',line)
    if m:
      level=len(m.group(1))-1
      title=m.group(2).strip()
      a=re.sub(r'[^a-z0-9 -]','',title.lower()).replace(' ','-')
      heads.append((level,title,a))
  if not heads: continue
  toc=['<!-- TOC-BEGIN -->','## Table of Contents','']
  for lv,tt,a in heads:
    toc.append(('  '*(lv-1))+f'- [{tt}](#{a})')
  toc.append('<!-- TOC-END -->\n')
  import re as _r
  if _r.search(r'^# .+?$',t,flags=_r.M):
    t=_r.sub(r'(^# .+?$)',lambda m:m.group(1)+'\n\n'+"\n".join(toc),t,count=1,flags=_r.M)
  p.write_text(t,encoding='utf-8')
