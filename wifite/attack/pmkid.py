diff --git a/wifite/attack/pmkid.py b/wifite/attack/pmkid.py
index f94b8e2..0d1d8e6 100644
--- a/wifite/attack/pmkid.py
+++ b/wifite/attack/pmkid.py
@@ -1,7 +1,8 @@
-import os
-import time
-import re
-from shutil import copy
+import os
+import time
+import re
+from shutil import copy
 
-from ..tools.aircrack import Aircrack
-from ..config import Configuration
-from ..util.color import Color
-from ..attack import Attack
+from ..tools.aircrack import Aircrack
+from ..config import Configuration
+from ..util.color import Color
+from ..attack import Attack
 
-class AttackPMKID(Attack):
-    def __init__(self, target):
-        super(AttackPMKID, self).__init__(target)
-        self.crack_result = None
-        self.keep_capturing = None
-        self.pcapng_file = Configuration.temp('pmkid.pcapng')
-        self.success = False
-        self.timer = None
+class AttackPMKID(Attack):
+    def __init__(self, target):
+        super(AttackPMKID, self).__init__(target)
+        self.crack_result = None
+        self.keep_capturing = None
+        self.pcapng_file = Configuration.temp('pmkid.pcapng')
+        self.success = False
+        self.timer = None
 
-    @staticmethod
-    def get_existing_pmkid_file(bssid):
-        if not os.path.exists(Configuration.wpa_handshake_dir):
-            return None
-
-        bssid = bssid.lower().replace(':', '')
-
-        file_re = re.compile(r'.*pmkid_.*\.22000')
-        for filename in os.listdir(Configuration.wpa_handshake_dir):
-            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
-            if not os.path.isfile(pmkid_filename):
-                continue
-            if not re.match(file_re, pmkid_filename):
-                continue
-
-            with open(pmkid_filename, 'r') as pmkid_handle:
-                pmkid_hash = pmkid_handle.read().strip()
-                if pmkid_hash.count('*') < 3:
-                    continue
-                existing_bssid = pmkid_hash.split('*')[1].lower().replace(':', '')
-                if existing_bssid == bssid:
-                    return pmkid_filename
-        return None
-
-    def run_aircrack(self):
-        if Configuration.dont_use_pmkid:
-            self.success = False
-            return False
-
-        pmkid_file = None
-        if not Configuration.ignore_old_handshakes:
-            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
-            if pmkid_file is not None:
-                Color.pattack('PMKID', self.target, 'CAPTURE',
-                              'Loaded {C}existing{W} PMKID hash: {C}%s{W}\n' % pmkid_file)
-        if pmkid_file is None:
-            pmkid_file = self.capture_pmkid()
-        if pmkid_file is None:
-            Color.pl('{!} PMKID hash not found')
-            return False
-        if Configuration.skip_crack:
-            Color.pl('{+} Cracking PMKID skipped due to {C}skip-crack{W}')
-            self.success = False
-            return True
-        key = Aircrack.crack_pmkid(pmkid_file, verbose=True)
-        if key:
-            Color.pl('{+} Key found: {G}%s{W}' % key)
-            from ..model.pmkid_result import CrackResultPMKID
-            result = CrackResultPMKID(self.target.bssid, self.target.essid, pmkid_file, key)
-            result.save()
-            self.crack_result = result
-            self.success = True
-        else:
-            Color.pl('{!} Key not found')
-            self.success = False
-        return True
-
-    def run(self):
-        self.run_aircrack()
+    @staticmethod
+    def get_existing_pmkid_file(bssid):
+        if not os.path.exists(Configuration.wpa_handshake_dir):
+            return None
+
+        bssid = bssid.lower().replace(':', '')
+        file_re = re.compile(r'.*pmkid_.*\.22000')
+        for filename in os.listdir(Configuration.wpa_handshake_dir):
+            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
+            if not os.path.isfile(pmkid_filename):
+                continue
+            if not re.match(file_re, pmkid_filename):
+                continue
+            with open(pmkid_filename, 'r') as pmkid_handle:
+                pmkid_hash = pmkid_handle.read().strip()
+                if pmkid_hash.count('*') < 3:
+                    continue
+                existing_bssid = pmkid_hash.split('*')[1].lower().replace(':', '')
+                if existing_bssid == bssid:
+                    return pmkid_filename
+        return None
+
+    def run_aircrack(self):
+        if Configuration.dont_use_pmkid:
+            self.success = False
+            return False
+        pmkid_file = None
+        if not Configuration.ignore_old_handshakes:
+            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
+            if pmkid_file is not None:
+                Color.pattack('PMKID', self.target, 'CAPTURE',
+                              'Загружен {C}существующий{W} PMKID hash: {C}%s{W}\n' % pmkid_file)
+        if pmkid_file is None:
+            pmkid_file = self.capture_pmkid()
+        if pmkid_file is None:
+            Color.pl('{!} Хэш PMKID не найден')
+            return False
+        if Configuration.skip_crack:
+            Color.pl('{+} Подбор PMKID пропущен из-за {C}skip-crack{W}')
+            self.success = False
+            return True
+        key = Aircrack.crack_pmkid(pmkid_file, verbose=True)
+        if key:
+            Color.pl('{+} Ключ найден: {G}%s{W}' % key)
+            from ..model.pmkid_result import CrackResultPMKID
+            result = CrackResultPMKID(self.target.bssid, self.target.essid, pmkid_file, key)
+            result.save()
+            self.crack_result = result
+            self.success = True
+        else:
+            Color.pl('{!} Ключ не найден')
+            self.success = False
+        return True
+
+    def run(self):
+        self.run_aircrack()
 
diff --git a/wifite/model/pmkid_result.py b/wifite/model/pmkid_result.py
index 1b2d0f1..7b3c2e9 100644
--- a/wifite/model/pmkid_result.py
+++ b/wifite/model/pmkid_result.py
@@ -1,26 +1,36 @@
 #!/usr/bin/env python
 # -*- coding: utf-8 -*-
 
 from ..util.color import Color
 from .result import CrackResult
 
 class CrackResultPMKID(CrackResult):
-    def __init__(self, bssid, essid, pmkid_file, key):
-        self.result_type = 'PMKID'
-        self.bssid = bssid
-        self.essid = essid
-        self.pmkid_file = pmkid_file
-        self.key = key
-        super(CrackResultPMKID, self).__init__()
-
-    def dump(self):
-        if self.essid:
-            Color.pl('{+} ESSID: {C}%s{W}' % self.essid)
-        if self.bssid:
-            Color.pl('{+} BSSID: {C}%s{W}' % self.bssid)
-        Color.pl('{+} Encryption: {C}%s{W}' % self.result_type)
-        if self.pmkid_file:
-            Color.pl('{+} PMKID file: {C}%s{W}' % self.pmkid_file)
-        if self.key:
-            Color.pl('{+} Key: {G}%s{W}' % self.key)
-        else:
-            Color.pl('{!} Key not found')
-
-    def print_single_line(self, longest_essid):
-        self.print_single_line_prefix(longest_essid)
-        Color.p('{G}%s{W}' % 'PMKID'.ljust(5))
-        Color.p('  ')
-        Color.p('Key: {G}%s{W}' % self.key)
-        Color.pl('')
-
-    def to_dict(self):
-        return {
-            'type': self.result_type,
-            'date': self.date,
-            'essid': self.essid,
-            'bssid': self.bssid,
-            'key': self.key,
-            'pmkid_file': self.pmkid_file
-        }
+    def __init__(self, bssid, essid, pmkid_file, key):
+        self.result_type = 'PMKID'
+        self.bssid = bssid
+        self.essid = essid
+        self.pmkid_file = pmkid_file
+        self.key = key
+        super(CrackResultPMKID, self).__init__()
+
+    def dump(self):
+        if self.essid:
+            Color.pl(f'{{+}} {"Имя точки доступа".rjust(19)}: {{C}}{self.essid}{{W}}')
+        if self.bssid:
+            Color.pl(f'{{+}} {"BSSID точки доступа".rjust(19)}: {{C}}{self.bssid}{{W}}')
+        Color.pl('{+} %s: {C}%s{W}' % ('Шифрование'.rjust(19), self.result_type))
+        if self.pmkid_file:
+            Color.pl('{+} %s: {C}%s{W}' % ('Файл PMKID'.rjust(19), self.pmkid_file))
+        if self.key:
+            Color.pl('{+} %s: {G}%s{W}' % ('Пароль (PSK)'.rjust(19), self.key))
+        else:
+            Color.pl('{!} %s  {O}ключ не найден{W}' % ''.rjust(19))
+
+    def print_single_line(self, longest_essid):
+        self.print_single_line_prefix(longest_essid)
+        Color.p('{G}%s{W}' % 'PMKID'.ljust(5))
+        Color.p('  ')
+        Color.p('Key: {G}%s{W}' % self.key)
+        Color.pl('')
+
+    def to_dict(self):
+        return {
+            'type': self.result_type,
+            'date': self.date,
+            'essid': self.essid,
+            'bssid': self.bssid,
+            'key': self.key,
+            'pmkid_file': self.pmkid_file
+        }
 
diff --git a/wifite/tools/aircrack.py b/wifite/tools/aircrack.py
index 9f2b43d..6d5f8a2 100644
--- a/wifite/tools/aircrack.py
+++ b/wifite/tools/aircrack.py
@@ ... @@
+    @staticmethod
+    def crack_pmkid(pmkid_file, wordlist=None, verbose=False):
+        """
+        Подбор PMKID с помощью aircrack-ng.
+        """
+        if wordlist is None:
+            wordlist = Configuration.wordlist
+        cap_file = pmkid_file
+        if pmkid_file.endswith('.22000'):
+            cap_file = pmkid_file.replace('.22000', '.cap')
+            # Конвертация PMKID в .cap
+            Process(['hcxpcapngtool', '-o', cap_file, pmkid_file]).wait()
+        command = ['aircrack-ng', '-w', wordlist, '-l', cap_file + '.key', cap_file]
+        if verbose:
+            Color.pl('{+} Запуск: %s' % ' '.join(command))
+        proc = Process(command)
+        proc.wait()
+        key_file = cap_file + '.key'
+        if os.path.exists(key_file):
+            with open(key_file) as f:
+                key = f.read().strip()
+            os.remove(key_file)
+            return key
+        return None
diff --git a/wifite/util/crack.py b/wifite/util/crack.py
index 14a1ad2..7f1d4e8 100644
--- a/wifite/util/crack.py
+++ b/wifite/util/crack.py
@@ ... @@
-        Color.p('\n{+} Enter {C}crack tool{W} ({C}%s{W}): {G}' % (
-            '{W}, {C}'.join(available_tools)))
-        tool_name = input()
-        Color.p('{W}')
-        if tool_name not in available_tools:
-            Color.pl('{!} {R}"%s"{O} tool not found, using {C}aircrack{W}' % tool_name)
-            tool_name = 'aircrack'
+        # Предлагаем выбор инструмента, но по умолчанию допускаем aircrack-ng для PMKID
+        Color.p('\n{+} Введите {C}инструмент для подбора{W} ({C}%s{W}): {G}' % (
+            '{W}, {C}'.join(available_tools)))
+        tool_name = input()
+        Color.p('{W}')
+        if tool_name not in available_tools:
+            Color.pl('{!} {R}"%s"{O} инструмент не найден, используется {C}aircrack{W}' % tool_name)
+            tool_name = 'aircrack'
diff --git a/README.md b/README.md
index 1234567..e89abcd 100644
--- a/README.md
+++ b/README.md
@@ ... @@
+* [`aircrack-ng`](https://www.aircrack-ng.org/): Для подбора паролей PMKID (используется вместо hashcat).
+   * [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool): Для захвата PMKID.
+   * [`hcxpcapngtool`](https://github.com/ZerBea/hcxtools): Для конвертации PMKID в .cap для aircrack-ng.
+
+## Установка зависимостей (Alpine Linux)
+
+```sh
+apk add aircrack-ng python3 py3-pip hcxpcapng hcxdumptool
+pip3 install -r requirements.txt
+```
