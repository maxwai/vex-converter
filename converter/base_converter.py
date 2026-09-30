from abc import abstractmethod, ABC
from typing import Any


class BaseConverter(ABC):
    @staticmethod
    @abstractmethod
    def convert(input_data: dict[str, Any]) -> dict[str, Any]:
        pass
