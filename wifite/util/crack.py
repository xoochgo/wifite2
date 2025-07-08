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

# ... (остальной код без изменений выше) ...

        # Предлагаем выбор инструмента, но по умолчанию допускаем aircrack-ng для PMKID
        Color.p('\n{+} Введите {C}инструмент для подбора{W} ({C}%s{W}): {G}' % (
            '{W}, {C}'.join(available_tools)))
        tool_name = input()
        Color.p('{W}')
        if tool_name not in available_tools:
            Color.pl('{!} {R}"%s"{O} инструмент не найден, используется {C}aircrack{W}' % tool_name)
            tool_name = 'aircrack'

# ... (остальной код без изменений ниже) ...
