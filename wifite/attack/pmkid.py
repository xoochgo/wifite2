#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..util.color import Color
from ..config import Configuration
from ..tools.aircrack import Aircrack
import os
import re
import time

class AttackPMKID(Attack):
    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.keep_capturing = None
        self.pcapng_file = Configuration.temp('pmkid.pcapng')
        self.success = False
        self.timer = None

    @staticmethod
    def get_existing_pmkid_file(bssid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')

        file_re = re.compile(r'.*pmkid_.*\.22000')
        for filename in os.listdir(Configuration.wpa_handshake_dir):
            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if not os.path.isfile(pmkid_filename):
                continue
            if not re.match(file_re, pmkid_filename):
                continue

            with open(pmkid_filename, 'r') as pmkid_handle:
                pmkid_hash = pmkid_handle.read().strip()
                if pmkid_hash.count('*') < 3:
                    continue
                existing_bssid = pmkid_hash.split('*')[1].lower().replace(':', '')
                if existing_bssid == bssid:
                    return pmkid_filename
        return None

    def run_aircrack(self):
        if Configuration.dont_use_pmkid:
            self.success = False
            return False

        pmkid_file = None
        if not Configuration.ignore_old_handshakes:
            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                              'Загружен {C}существующий{W} PMKID hash: {C}%s{W}\n' % pmkid_file)
        if pmkid_file is None:
            pmkid_file = self.capture_pmkid()
        if pmkid_file is None:
            Color.pl('{!} Хэш PMKID не найден')
            return False
        if Configuration.skip_crack:
            Color.pl('{+} Подбор PMKID пропущен из-за {C}skip-crack{W}')
            self.success = False
            return True
        key = Aircrack.crack_pmkid(pmkid_file, verbose=True)
        if key:
            Color.pl('{+} Ключ найден: {G}%s{W}' % key)
            from ..model.pmkid_result import CrackResultPMKID
            result = CrackResultPMKID(self.target.bssid, self.target.essid, pmkid_file, key)
            result.save()
            self.crack_result = result
            self.success = True
        else:
            Color.pl('{!} Ключ не найден')
            self.success = False
        return True

    def capture_pmkid(self):
        # Здесь должна быть реализация захвата PMKID, например через hcxdumptool/hcxtools.
        # Пока просто выводим предупреждение.
        Color.pl('{!} Захват PMKID не реализован. Добавьте реализацию с использованием hcxdumptool/hcxtools.')
        return None

    def run(self):
        self.run_aircrack()
