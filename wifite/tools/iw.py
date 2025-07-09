import subprocess

class Iw:
    @staticmethod
    def is_monitor(interface):
        """
        Проверяет, находится ли интерфейс в режиме monitor.
        Возвращает True, если интерфейс в режиме monitor, иначе False.
        """
        try:
            # Пробуем с помощью iwconfig (классический способ)
            output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode(errors="ignore")
            for line in output.splitlines():
                if 'Mode:Monitor' in line:
                    return True
                if 'monitor mode' in line.lower():
                    return True
            # Альтернативно, используем `iw dev` (современные системы)
            iw_output = subprocess.check_output(['iw', 'dev', interface, 'info'], stderr=subprocess.STDOUT).decode(errors="ignore")
            for line in iw_output.splitlines():
                if 'type monitor' in line.lower():
                    return True
        except Exception:
            pass
        return False
