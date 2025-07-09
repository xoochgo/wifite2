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
    def fails_dependency_check():
        """Зависимость всегда считается установленной (iw всегда есть, если модуль работает)"""
        try:
            subprocess.check_output(['iw', '--version'], stderr=subprocess.STDOUT)
            return False
        except Exception:
            return True

    @staticmethod
    def install_instructions():
        return "Установите пакет 'iw' через ваш пакетный менеджер, например: sudo apt install iw"
