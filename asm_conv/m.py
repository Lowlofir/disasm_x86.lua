import codecs
import itertools
from operator import attrgetter, itemgetter
import struct
import time
import cProfile
from collections import defaultdict
from pathlib import Path
# from pstats import SortKey
from typing import *

from lxml import etree
from export import *
from pprint import pprint
# from dotmap import DotMap

class hexint(int):
    def __str__(self):
        return hex(self)

    def __repr__(self):
        return hex(self)

class hexbytes(bytes):
    def __str__(self):
        return self.hex()

    def __repr__(self):
        return self.hex()


class dotview:
    def __init__(self, d: Mapping):
        self.d = d

    def __getattr__(self, k):
        return self.d.get(k)


class wdict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dw = dotview(self)

    def __getattr__(self, k):
        return self.get(k)


tree = etree.parse(open('x86reference.xml'))

ddd = set()

cmds = dict()


def extract():
    def make_imm(tstr: str):
        imm = None
        if tstr.startswith('b'):
            imm = {'s': 1}
        elif tstr == 'w':
            imm = {'s': 2}
        elif tstr in ('v', 'vds', 'vqp'):
            rexw = 'uimpl'
            x66 = 'uimpl'
            if tstr == 'vqp':
                rexw = 'promote'
                x66 = 2
            elif tstr == 'vds':
                rexw = 'sign-ext'
                x66 = 2
            imm = {'s': 4, 'rexw': rexw, 'x66': x66}
        elif tstr == 'vs':   # push 68
            imm = {'s': 4, 'rexw': 'ignore', 'x66': 2}
            el['debug'] = True
            # print("tstr == 'vs'")
            # print(hex(el['opcd_pri']), el['opcd_sz'])
        else:
            raise Exception
        return imm

    def make_moffs(astr: str):
        if astr == 'O':
            imm = {'s': 'addr'}
        else:
            raise Exception
        return imm


    els = []
    prefs = []
    for pri_opcd_node in tree.xpath('//pri_opcd'):
        pri_opcd = hexint(pri_opcd_node.get('value'), base=16)
        if pri_opcd == 0x0F: continue
        pri_sz = 1 if pri_opcd_node.getparent().tag == 'one-byte' else 2
        pri_valid_32_only = False
        pri_opcd_els = []
        pri_opcd_prefs = []
        for el_node in pri_opcd_node.findall('entry'):
            el = wdict()

            if (opcd_supp_end_node := el_node.find('proc_end')) is not None:
                opcd_supp_end = int(opcd_supp_end_node.text)
                if opcd_supp_end < 10:
                    continue

            el['only_32'] = False
            el['only_64'] = False
            el_is_prefix = False
            # if el_node.get('ring', '3') not in ('3', 'f'):
            #     continue
            if el_node.get('mode') == 'e':
                if el_node.get('attr') == 'invd':
                    pri_valid_32_only = True
                    continue
                else:
                    el['only_64'] = True
            note = el_node.find('note/brief')
            if note is not None:
                el['desc'] = note.text + ''.join(etree.tostring(e, encoding='unicode') for e in note)

            el['opcd_pri'] = pri_opcd
            el['opcd_sz'] = pri_sz
            if (opcd_ext := el_node.find('opcd_ext')) is not None:
                el['opcd_ext'] = int(opcd_ext.text, base=16)
            if (opcd_sec := el_node.find('sec_opcd')) is not None:
                el['opcd_sec'] = hexint(opcd_sec.text, base=16)
            if (opcd_pref := el_node.find('pref')) is not None:
                el['opcd_pref'] = hexint(opcd_pref.text, base=16)

            opcd_bit_d = el_node.get('direction')
            if opcd_bit_d is not None:
                el['bit_dir'] = int(opcd_bit_d)
            opcd_bit_w = el_node.get('op_size')
            if opcd_bit_w is not None:
                el['bit_size'] = int(opcd_bit_w)
            opcd_bit_s = el_node.get('sign-ext')
            if opcd_bit_s is not None:
                el['bit_sign'] = int(opcd_bit_s)

            if (opcd_mod := el_node.get('mod')) is not None:
                el['opcd_mod'] = opcd_mod

            if (opcd_attr := el_node.get('attr')) is not None:
                if opcd_attr in ('invd', 'undef', 'null', 'nop'):
                    el['attr'] = opcd_attr
                if opcd_attr == 'undef':
                    continue

            if (opcd_particular := el_node.get('particular')) is not None:
                el['particular'] = opcd_particular

            if 'opcd_ext' in el or el_node.get('r', 'no') == 'yes':
                el['modrm'] = True
            else:
                el['modrm'] = False

            if el_node.find('grp1') is not None and el_node.find('grp1').text == 'prefix':
                el_is_prefix = True
                assert 'opcd_ext' not in el
                assert 'opcd_sec' not in el
                assert 'opcd_pref' not in el

            syns = []
            syns_imms = []
            for syn_node in el_node.findall('syntax'):
                syn_imms = []
                syn = wdict({ 'mnem': None, 'mod': None, 'params': [] })
                if syn_node.get('mod'):
                    syn['mod'] = syn_node.get('mod')
                for syn_child in syn_node:
                    if syn_child.tag == 'mnem':
                        syn['mnem'] = syn_child.text
                    elif syn_child.tag in ('dst', 'src'):
                        pm = {'dir': syn_child.tag}
                        subels = len(syn_child.findall('*'))
                        if syn_child.text:
                            assert subels == 0
                            pm['value'] = syn_child.text
                            if syn_child.get('nr'):
                                pm['nr'] = syn_child.get('nr')
                                assert syn_child.get('group')
                                pm['group'] = syn_child.get('group')
                        else:
                            assert not syn_child.get('nr')
                            assert not syn_child.get('group')

                        if syn_child_addr := syn_child.get('address'):
                            pm['address'] = syn_child_addr
                        elif syn_child.find('a') is not None:
                            a = syn_child.find('a')
                            pm['address'] = a.text
                        if pm.get('address') == 'Z':
                            el.setdefault('opcd_bitfields', 0)
                            el['opcd_bitfields'] = el['opcd_bitfields'] | 7

                        if syn_child_type := syn_child.get('type'):
                            pm['vtype'] = syn_child_type
                        elif syn_child.find('t') is not None:
                            a = syn_child.find('t')
                            pm['vtype'] = a.text

                        if syn_child_depend := syn_child.get('depend'):
                            pm['depend'] = syn_child_depend
                            assert syn_child_depend=='no'

                        if pm.get('address') in ('I','J') and 'value' not in pm:
                            syn_imms.append(make_imm(pm['vtype']))
                        if pm.get('address') == 'O' and 'value' not in pm:
                            syn_imms.append(make_moffs(pm['address']))

                        pm['hidden'] = syn_child.get('displayed') == 'no'
                        syn['params'].append(pm)
                        # if syn_child.get('displayed') == 'no':
                        #     syn['hidden_params'].append(pm)
                        # else:
                        #     syn['params'].append(pm)
                syns.append(syn)
                syns_imms.append(syn_imms)
            el['syns'] = syns

            if len(syns_imms)>1 and any(syns_imms):
                for syn_imm_tpl in itertools.zip_longest(*syns_imms):
                    ref = syn_imm_tpl[0]
                    if not all(x==ref for x in syn_imm_tpl[1:]):
                        print('problem 1')
                        print(el)
            if syns_imms and syns_imms[0]:
                el['imms'] = syns_imms[0]

            if el['modrm'] == False:  # check if really should be False
                modrm_req = None
                for syn in syns:
                    for p in syn['params']:
                        if p.get('address') in ('A', 'O', 'Z'):
                            modrm_req = False
                            break
                        if p.get('address') == 'E':  # NOPs
                            modrm_req = True
                            break
                        if p.get('value') is None and p.get('address') not in ('I', 'J'):  # actually nothing
                            print(hex(el['opcd_pri']), el['opcd_sz'])
                            modrm_req = True
                            break
                    if modrm_req is not None: break
                if modrm_req:
                    el['modrm'] = True

            if el_is_prefix:
                pri_opcd_prefs.append(el)
            else:
                pri_opcd_els.append(el)

        for e in pri_opcd_els:
            e['only_32'] = pri_valid_32_only
        els.extend(pri_opcd_els)
        prefs.extend(pri_opcd_prefs)
    return els, prefs

def process(els: List[wdict]):
    # def print_signature(s):
    #     print('{}, {}, {}, {}'.format(s[0].hex(), s[1].hex(), s[2], s[3]))

    def make_signature(s, *args):
        def intlist_to_bytes(l, s):
            return hexbytes(b''.join(i.to_bytes(1, 'little', signed=s) for i in l))
        vs, bms = zip(*s)
        # print(vs, bms)
        vsb = intlist_to_bytes(vs, False)
        bmsb = intlist_to_bytes(bms, True)
        return vsb, bmsb, *args

    def compute_signatures(els):  # opcd_pri opcd_sec opcd_ext
        for el in els:
            dm = dotview(el)
            bytelst = []
            if dm.opcd_pref:
                bytelst.append((dm.opcd_pref, ~0))
            if dm.opcd_sz == 2:
                bytelst.append((0x0F, ~0))
            if dm.opcd_bitfields:
                bytelst.append((dm.opcd_pri, ~dm.opcd_bitfields))
            else:
                bytelst.append((dm.opcd_pri, ~0))
            if dm.opcd_sec:
                bytelst.append((dm.opcd_sec, ~0))
            if dm.opcd_ext:
                bytelst.append((dm.opcd_ext<<3, ~(7<<3)))
            el.btuple = make_signature(bytelst, dm.opcd_mod, dm.only_64, dm.attr, dm.particular)

    def innumerate(ll):
        for i,el in enumerate(ll):
            el.i = i

    def merge_entries(groups: List[List[wdict]]):
        print('ENTRIES GROUPS', len(groups))
        moved_i = set()
        merged_sgn = []
        for g in groups:
            merged_sgn.append((g[0].btuple[0], g[0].btuple[3]))
            g.sort(key=lambda x: x.i)
            # pprint(g)
            assert all(e['opcd_pri'] == g[0]['opcd_pri'] for e in g)
            for e in g[1:]:
                g[0].syns.extend(e.syns)
                e['dbg_outmerged'] = True
                moved_i.add(e.i)
        print('OUTMERGED', len(moved_i))
        print(sorted(merged_sgn))
        return [e for e in els if e.i not in moved_i]

    def get_unseparable_groups(els, kf):
        sels = sorted(els, key=kf)
        groups = []
        keys = []
        for k, g in itertools.groupby(sels, key=kf):
            l = list(g)
            if len(l) <= 1: continue
            groups.append(l)
            keys.append(l[0].btuple)
            # print_signature(k)
        return groups, keys

    innumerate(els)
    compute_signatures(els)
    kf = lambda x: (hash(x.btuple), x.btuple[0])
    groups, keys = get_unseparable_groups(els, kf)
    # print(keys)
    els = merge_entries(groups)

    def adjust_types_for_synonimisation(els):
        def pkey(p):
            return frozenset((k,v) for k,v in p.items() if k not in ('value','vtype'))
        def skey(s):
            return (s.mnem,) + tuple(pkey(p) for p in s.params)
        def intercut(pl1, pl2):
            assert len(pl1)==len(pl2)
            assert all(pkey(p1)==pkey(p2) for p1,p2 in zip(pl1, pl2)), pl1
            c = 0
            for p1,p2 in zip(pl1, pl2):
                if p2['vtype'] == 'v' and p1['vtype'] == 'wo':
                    p2['vtype'] = 'do'
                    c+=1
            return c

        c2 = 0
        for el in els:
            synargs = defaultdict(list)
            for s in el.syns:
                if skey(s) in synargs:
                    c = intercut(synargs[skey(s)][-1], s.params)
                    if c==0:
                        print('c==0', el.btuple[0], el.btuple[3])
                    else:
                        # print(el.btuple[0], el.btuple[3], c, 'types adjusted')
                        c2+=1
                synargs[skey(s)].append(s.params)
        print('TYPES ADJUSTED', c2)

    adjust_types_for_synonimisation(els)

    def merge_syns_mnem(el, g):
        moved_i = set()
        g.sort(key=attrgetter('i'))
        g[0]['mnem'] = [ g[0].mnem ]
        for s in g[1:]:
            g[0].mnem.append(s.mnem)
            moved_i.add(s.i)
        return [s for s in el.syns if s.i not in moved_i]

    def syn_hash1(syn):
        return tuple( [syn.get('mod')] + [frozenset(d.items()) for d in syn['params']] )

    def group_syns(el, hf):
        grouped_syns = defaultdict(list)
        for syn in el.syns:
            grouped_syns[hf(syn)].append(syn)
        groups = [g for g in grouped_syns.values() if len(g) > 1]
        return groups


    syns_groups_n = 0
    for el in els:
        if len(el.syns)<=1: continue
        groups = group_syns(el, syn_hash1)
        if groups:
            assert len(groups) == 1
            gr = groups[0]
            # print(len(gr), ':', el.btuple, [s.mnem for s in gr])
            assert all(len(g.keys()-['params','mnem','mod'])==0 and g.get('mod') is None for g in gr)
            assert el.syns == gr
            innumerate(el.syns)
            el['syns'] = merge_syns_mnem(el, gr)
            assert len(el['syns'])==1
            syns_groups_n += 1
    print('SYNS FULL SYNONYM GROUPS', syns_groups_n)
    multisyns = [e for e in els if len(e.syns)>1]
    print('MULTISYNS REMAINS', len(multisyns))

    def syn_hash_2(syn):  # ignore hidden/not hidden
        return tuple([syn.get('mod')] + [frozenset((k,v.lower()) for k,v in d.items() if k!='hidden') for d in syn['params']])

    def merge_syns_hidden(el, g):
        moved_i = set()
        g.sort(key=attrgetter('i'))
        g[0]['hsgroup'] = True
        assert all('mnem_list' not in s for s in g)
        g[0]['mnem'] = [ g[0].mnem ]
        for p in g[0].params:
            p['hidden'] = [ p['hidden'] ]
        for s in g[1:]:
            g[0].mnem.append(s.mnem)
            for i,p in enumerate(s.params):
                g[0].params[i]['hidden'].append(p['hidden'])
            moved_i.add(s.i)
        return [s for s in el.syns if s.i not in moved_i]

    c1, c2, c3 = 0, 0, 0
    hs_merged = []
    for el in els:
        if len(el.syns)<=1: continue
        c3 += 1
        groups = group_syns(el, syn_hash_2)
        if not groups: continue
        # assert len(groups)==1, el
        for g in groups:
            assert len(g)==2
            innumerate(el.syns)
            if len(g) != len(el.syns):
                c2 += 1
            else:
                c1 += 1
            el['syns'] = merge_syns_hidden(el, g)
            hs_merged.append(el.btuple[0])
            # print(el.btuple[0], el['syns'])
    print('MERGED BY H/S {}+{} of {}'.format(c1, c2, c3))
    print(hs_merged)

    # pprint([ (e.btuple[0],e.btuple[3]) for e in els if len(e.syns)>1 and all(s.mod==e.syns[0].mod for s in e.syns)])

    vtypes_tbl = { 'wo': {2}, 'do': {4}, 'qp': {8}, 'v': {2,4}, 'vds':{2,4,8}, 'vq':{4,2}, 'vqp':{2,4,8}, 'vs':{2,4}, \
                   'dqp':{4,8}, 'p':{2,4}, 'ptp':{2,4,8} }

    def code_vtype(vtype) -> Optional[Union[dict, int]]:
        vtt0 = { 'b':1, 'bs':1, 'bss':1, 'd':4, 'di':4, 'dq':16, 'dr':8, 'ds':4, 'pi':8, 'pd':16, 'ps':16, 'psq':8, \
                 'q':8, 'qi':8, 'sd':8, 'sr':4, 'ss':4, 'w':2, 'wi':2 }
        vtt = wdict({ vtname:{v:v for v in vtset} for vtname,vtset in vtypes_tbl.items() })
        vtt.vds[8] = 4
        vtt.vq[4] = 8
        del vtt['p']
        del vtt['ptp']
        vtt.update(vtt0)

        if vtype in vtt:
            return vtt[vtype]
        else:
            return None

    def replace_syns_types(syn):
        op_szs = set()
        for p in syn.params:
            if vtype := p.get('vtype'):
                p['vtype_raw'] = vtype
                if cvtype := code_vtype(vtype):
                    p['vtype'] = cvtype
                    if type(cvtype)==dict:
                        op_szs.update(cvtype.keys())
                else:
                    p['vtype'] = -1
        syn['op_szs'] = list(op_szs) if len(op_szs)>0 else None


    for el in els:
        grouped_syns = defaultdict(list)
        for syn in el.syns:
            grouped_syns[syn.mod].append(syn)
        for gr in grouped_syns.values():
            synvtypes = []
            for s in gr:
                parvtypes = []
                for p in s.params:
                    if p.get('vtype') in vtypes_tbl:
                        parvtypes.append(vtypes_tbl[p['vtype']])
                if len(parvtypes)>1 and not all(pvt==parvtypes[0] for pvt in parvtypes[1:]):
                    print('parvtypes anomaly:',el.btuple[0], el.btuple[3])
                    parvtypes[0].update(*parvtypes[1:])
                synvtypes.append(parvtypes[0] if parvtypes else None)
            if any(synvt==None for synvt in synvtypes) and not all(synvt==None for synvt in synvtypes):
                print('synvtypes anomaly:',el.btuple[0], el.btuple[3])

    for el in els:
        for syn in el.syns:
            replace_syns_types(syn)

    for el in els:
        for syn in el.syns:
            for p in syn.params:
                if p['hidden'] == False:
                    del p['hidden']



    return els



t1 = time.perf_counter()
els, prefixes = extract()
els = process(els)
t2 = time.perf_counter()

# pprint(els, width=120, indent=4)
print(sorted(ddd))
print(t2 - t1)

# print(serialize({ 'a':None, 'b':1, 'c':2, 'd':None, 'e':False}, False))
# print(serialize([ None, 1, 2, None, False], False))
t1 = time.perf_counter()
# cProfile.run("ser = write({'opcodes': els, 'prefixes': prefixes}, 'asm_db.lua', form=True)", sort=SortKey.TIME)
ser = write({'opcodes': els, 'prefixes': prefixes}, 'asm_db.lua', form=True)
t2 = time.perf_counter()
print(t2 - t1)
print(Path('asm_db.lua').stat().st_size/1024, 'KiB')
