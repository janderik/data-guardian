from abc import ABC, abstractmethod
from typing import Any


class BaseReporter(ABC):
    @abstractmethod
    def generate(self, results: Any, output_path: str = "") -> str:
        ...
