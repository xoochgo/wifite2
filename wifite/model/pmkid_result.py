#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..util.color import Color
from .result import CrackResult

class CrackResultPMKID(CrackResult):
    def __init__(self, bssid, essid, pmkid_file, key):
        self.result_type = 'PMKID'
        self.bssid = bssid
        self.essid = essid
        self.pmkid_file = pmkid_file
        self.key = key
        super(CrackResultPMKID, self).__init__()

    def dump(self):
        if self.essid:
            Color.pl(f'{{+}} {"Имя точки доступа".rjust(19)}: {{C}}{self.essid}{{W}}')
        if self.bssid:
            Color.pl(f'{{+}} {"BSSID точки доступа".rjust(19)}: {{C}}{self.bssid}{{W}}')
        Color.pl('{+} %s: {C}%s{W}' % ('Шифрование'.rjust(19), self.result_type))
        if self.pmkid_file:
            Color.pl('{+} %s: {C}%s{W}' % ('Файл PMKID'.rjust(19), self.pmkid_file))
        if self.key:
            Color.pl('{+} %s: {G}%s{W}' % ('Пароль (PSK)'.rjust(19), self.key))
        else:
            Color.pl('{!} %s  {O}ключ не найден{W}' % ''.rjust(19))

    def print_single_line(self, longest_essid):
        self.print_single_line_prefix(longest_essid)
        Color.p('{G}%s{W}' % 'PMKID'.ljust(5))
        Color.p('  ')
        Color.p('Key: {G}%s{W}' % self.key)
        Color.pl('')

    def to_dict(self):
        return {
            'type': self.result_type,
            'date': self.date,
            'essid': self.essid,
            'bssid': self.bssid,
            'key': self.key,
            'pmkid_file': self.pmkid_file
        }
