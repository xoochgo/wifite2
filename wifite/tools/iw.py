import subprocess

class Iw:
    @staticmethod
    def is_monitor(interface):
        """
        Проверяет, находится ли интерфейс в режиме monitor.
        Возвращает True, если интерфейс в режиме monitor, иначе False.
        """
        try:
            output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode(errors="ignore")
            for line in output.splitlines():
                if 'Mode:Monitor' in line:
                    return True
                if 'monitor mode' in line.lower():
                    return True
            iw_output = subprocess.check_output(['iw', 'dev', interface, 'info'], stderr=subprocess.STDOUT).decode(errors="ignore")
            for line in iw_output.splitlines():
                if 'type monitor' in line.lower():
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def get_interfaces(mode=None):
        """
        Возвращает список беспроводных интерфейсов.
        Если указан mode='monitor', возвращает только интерфейсы в режиме monitor.
        """
        import re
        interfaces = []
        try:
            # Сначала пробуем через iw dev
            output = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT).decode(errors="ignore")
            blocks = output.split('\n\n')
            for block in blocks:
                name = None
                type_ = None
                for line in block.splitlines():
                    if 'Interface' in line:
                        name = line.split()[-1]
                    if 'type' in line:
                        type_ = line.split()[-1]
                if name:
                    if mode == 'monitor':
                        if type_ == 'monitor':
                            interfaces.append(name)
                    else:
                        interfaces.append(name)
            # Если ничего не нашли — пробуем iwconfig
            if not interfaces:
                output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode(errors="ignore")
                for line in output.splitlines():
                    if not line or line.startswith(' '):
                        continue
                    iface = line.split()[0]
                    if 'no wireless extensions' in line:
                        continue
                    if mode == 'monitor':
                        if 'Mode:Monitor' in line:
                            interfaces.append(iface)
                    else:
                        interfaces.append(iface)
        except Exception:
            pass
        return interfaces

    @staticmethod
    def fails_dependency_check():
        """
        Проверяет, установлена ли утилита iw.
        Возвращает True, если зависимость не установлена (то есть утилита недоступна).
        """
        try:
            subprocess.check_output(['iw', '--version'], stderr=subprocess.STDOUT)
            return False
        except Exception:
            return True

    @staticmethod
    def install_instructions():
        """
        Возвращает инструкцию по установке утилиты iw.
        """
        return "Установите пакет 'iw' через ваш пакетный менеджер, например: sudo apt install iw"
