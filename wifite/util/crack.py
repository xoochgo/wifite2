#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from json import loads
from ..config import Configuration
from ..model.handshake import Handshake
from ..model.pmkid_result import CrackResultPMKID
from ..model.wpa_result import CrackResultWPA
from ..tools.aircrack import Aircrack
from ..tools.cowpatty import Cowpatty
from ..tools.hashcat import Hashcat, HcxPcapngTool
from ..tools.john import John
from ..util.color import Color
from ..util.process import Process

# Дальше должен идти класс или функции, отступ 0
class CrackHelper:
    # методы класса с отступом 4 пробела
    ...

    TYPES = {
        '4-WAY': '4-Way Handshake',
        'PMKID': 'PMKID Hash'
    }

    # Tools for cracking & their dependencies.
    possible_tools = [
        ('aircrack', [Aircrack]),
        ('hashcat', [Hashcat, HcxPcapngTool]),
        ('john', [John, HcxPcapngTool]),
        ('cowpatty', [Cowpatty])
    ]

    @classmethod
    def run(cls):
        Configuration.initialize(False)

        # Get wordlist
        if not Configuration.wordlist:
            Color.p('\n{+} Введите путь к словарю для подбора: {G}')
            Configuration.wordlist = input()
            Color.p('{W}')
            if not os.path.exists(Configuration.wordlist):
                Color.pl('{!} {R}Словарь {O}%s{R} не найден. Выход.' % Configuration.wordlist)
                return
            Color.pl('')

        # Get handshakes
        handshakes = cls.get_handshakes()
        if len(handshakes) == 0:
            Color.pl('{!} {O}Рукопожатий не найдено{W}')
            return

        hs_to_crack = cls.get_user_selection(handshakes)
        all_pmkid = all(hs['type'] == 'PMKID' for hs in hs_to_crack)

        # Identify missing tools
        missing_tools = []
        available_tools = []
        for tool, dependencies in cls.possible_tools:
            if any(not Process.exists(dep.dependency_name) for dep in dependencies):
                missing_tools.append(tool)
            else:
                available_tools.append(tool)

        if missing_tools:
            Color.pl('\n{!} {O}Недоступные инструменты (установите для активации):{W}')
            for tool in missing_tools:
                Color.pl('     {R}* {R}%s{W}' % tool)

        # Предлагаем выбор инструмента, но по умолчанию допускаем aircrack-ng для PMKID
        Color.p('\n{+} Введите {C}инструмент для подбора{W} ({C}%s{W}): {G}' % (
            '{W}, {C}'.join(available_tools)))
        tool_name = input()
        Color.p('{W}')
        if tool_name not in available_tools:
            Color.pl('{!} {R}"%s"{O} инструмент не найден, используется {C}aircrack{W}' % tool_name)
            tool_name = 'aircrack'

        try:
            for hs in hs_to_crack:
                cls.crack(hs, tool_name)
        except KeyboardInterrupt:
            Color.pl('\n{!} {O}Прервано пользователем{W}')

    @classmethod
    def is_cracked(cls, file):
        if not os.path.exists(Configuration.cracked_file):
            return False
        with open(Configuration.cracked_file) as f:
            json = loads(f.read())
        if json is None:
            return False
        for result in json:
            for k in list(result.keys()):
                v = result[k]
                if 'file' in k and os.path.basename(v) == file:
                    return True
        return False

    @classmethod
    def get_handshakes(cls):
        handshakes = []
        skipped_pmkid_files = skipped_cracked_files = 0

        hs_dir = Configuration.wpa_handshake_dir
        if not os.path.exists(hs_dir) or not os.path.isdir(hs_dir):
            Color.pl('\n{!} {O}директория не найдена: {R}%s{W}' % hs_dir)
            return []

        Color.pl('\n{+} Список захваченных рукопожатий из {C}%s{W}:\n' % os.path.abspath(hs_dir))
        for hs_file in os.listdir(hs_dir):
            if hs_file.count('_') != 3:
                continue

            if cls.is_cracked(hs_file):
                skipped_cracked_files += 1
                continue

            if hs_file.endswith('.cap'):
                hs_type = '4-WAY'
            elif hs_file.endswith('.22000'):
                hs_type = 'PMKID'
            else:
                continue

            name, essid, bssid, date = hs_file.split('_')
            date = date.rsplit('.', 1)[0]
            days, hours = date.split('T')
            hours = hours.replace('-', ':')
            date = f'{days} {hours}'

            if hs_type == '4-WAY':
                handshakenew = Handshake(os.path.join(hs_dir, hs_file))
                handshakenew.divine_bssid_and_essid()
                essid_discovery = handshakenew.essid
                essid = essid if essid_discovery is None else essid_discovery

            handshake = {
                'filename': os.path.join(hs_dir, hs_file),
                'bssid': bssid.replace('-', ':'),
                'essid': essid,
                'date': date,
                'type': hs_type
            }
            handshakes.append(handshake)

        if skipped_pmkid_files > 0:
            Color.pl('{!} {O}Пропущено %d *.22000 файлов (hashcat отсутствует).\n' % skipped_pmkid_files)
        if skipped_cracked_files > 0:
            Color.pl('{!} {O}Пропущено %d уже подобранных файлов.\n' % skipped_cracked_files)

        return sorted(handshakes, key=lambda x: x.get('date'), reverse=True)

    @classmethod
    def print_handshakes(cls, handshakes):
        max_essid_len = max([len(hs['essid']) for hs in handshakes] + [len('ESSID (truncated)')])
        Color.p('{W}{D}  NUM')
        Color.p('  ' + 'ESSID (truncated)'.ljust(max_essid_len))
        Color.p('  ' + 'BSSID'.ljust(17))
        Color.p('  ' + 'TYPE'.ljust(5))
        Color.p('  ' + 'DATE CAPTURED\n')
        Color.p('  ---')
        Color.p('  ' + ('-' * max_essid_len))
        Color.p('  ' + ('-' * 17))
        Color.p('  ' + ('-' * 5))
        Color.p('  ' + ('-' * 19) + '{W}\n')

        for index, handshake in enumerate(handshakes, start=1):
            Color.p('  {G}%s{W}' % str(index).rjust(3))
            Color.p('  {C}%s{W}' % handshake['essid'].ljust(max_essid_len))
            Color.p('  {O}%s{W}' % handshake['bssid'].ljust(17))
            Color.p('  {C}%s{W}' % handshake['type'].ljust(5))
            Color.p('  {W}%s{W}\n' % handshake['date'])

    @classmethod
    def get_user_selection(cls, handshakes):
        cls.print_handshakes(handshakes)
        Color.p(
            '{+} Выберите рукопожатие(я) для подбора ({G}%d{W}-{G}%d{W}, несколько через {C},{W} или {C}-{W} или {C}all{W}): {G}' %
            (1, len(handshakes))
        )
        choices = input()
        Color.p('{W}')
        selection = []
        for choice in choices.split(','):
            if '-' in choice:
                first, last = [int(x) for x in choice.split('-')]
                for index in range(first, last + 1):
                    selection.append(handshakes[index - 1])
            elif choice.strip().lower() == 'all':
                selection = handshakes[:]
                break
            elif choice.strip().isdigit():
                index = int(choice)
                selection.append(handshakes[index - 1])
        return selection

    @classmethod
    def crack(cls, hs, tool):
        Color.pl('\n{+} Подбор для {G}%s {C}%s{W} ({C}%s{W})' % (
            cls.TYPES[hs['type']], hs['essid'], hs['bssid']))

        if hs['type'] == 'PMKID':
            crack_result = cls.crack_pmkid(hs, tool)
        elif hs['type'] == '4-WAY':
            crack_result = cls.crack_4way(hs, tool)
        else:
            raise ValueError(f'Unknown handshake type: {hs["type"]} Handshake={hs}')

        if crack_result is None:
            Color.pl('{!} {R}Не удалось подобрать {O}%s{R} ({O}%s{R}): Пароль не найден в словаре' % (
                hs['essid'], hs['bssid']))
        else:
            Color.pl('{+} {G}Пароль подобран!{W} {C}%s{W} ({C}%s{W}). Ключ: "{G}%s{W}"' % (
                hs['essid'], hs['bssid'], crack_result.key))
            crack_result.save()

    @classmethod
    def crack_4way(cls, hs, tool):
        handshake = Handshake(hs['filename'],
                              bssid=hs['bssid'],
                              essid=hs['essid'])
        try:
            handshake.divine_bssid_and_essid()
        except ValueError as e:
            Color.pl('{!} {R}Ошибка: {O}%s{W}' % e)
            return None

        key = None
        if tool == 'aircrack':
            key = Aircrack.crack_handshake(handshake, show_command=True)
        elif tool == 'hashcat':
            key = Hashcat.crack_handshake(handshake, show_command=True)
        elif tool == 'john':
            key = John.crack_handshake(handshake, show_command=True)
        elif tool == 'cowpatty':
            key = Cowpatty.crack_handshake(handshake, show_command=True)

        if key is not None:
            return CrackResultWPA(hs['bssid'], hs['essid'], hs['filename'], key)
        else:
            return None

    @classmethod
    def crack_pmkid(cls, hs, tool):
        key = None
        if tool == 'aircrack':
            key = Aircrack.crack_pmkid(hs['filename'], verbose=True)
        elif tool == 'hashcat':
            key = Hashcat.crack_pmkid(hs['filename'], verbose=True)
        elif tool == 'john':
            key = John.crack_handshake(hs['filename'], show_command=True)
        # cowpatty обычно не для PMKID

        if key is not None:
            return CrackResultPMKID(hs['bssid'], hs['essid'], hs['filename'], key)
        else:
            return None

if __name__ == '__main__':
    CrackHelper.run()
