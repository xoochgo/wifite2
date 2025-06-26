from abc import ABC, abstractmethod

class Dependency(ABC):
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the dependency."""
        pass

    @abstractmethod
    def exists(self) -> bool:
        """Checks if the dependency is installed."""
        pass

    @abstractmethod
    def install(self) -> None:
        """Installs the dependency."""
        pass

    @abstractmethod
    def print_install(self) -> None:
        """Prints installation instructions for the dependency."""
        pass
