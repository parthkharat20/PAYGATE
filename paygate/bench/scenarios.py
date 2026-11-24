"""
Scenario loader and validator for PayGate-Bench 50-scenario dataset.
"""

import os
import yaml
from typing import Dict, Any, List


class ScenarioLoader:
    """Loads and provides access to Benign (25) and Adversarial (25) suites."""

    def __init__(
        self,
        benign_path: str = "paygate/bench/benign.yaml",
        adversarial_path: str = "paygate/bench/adversarial.yaml",
    ):
        self.benign_path = benign_path
        self.adversarial_path = adversarial_path

    def load_benign_scenarios(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.benign_path):
            raise FileNotFoundError(f"Benign dataset not found at {self.benign_path}")
        with open(self.benign_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("tasks", [])

    def load_adversarial_scenarios(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.adversarial_path):
            raise FileNotFoundError(f"Adversarial dataset not found at {self.adversarial_path}")
        with open(self.adversarial_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("attacks", [])

    def load_all_50_scenarios(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "benign": self.load_benign_scenarios(),
            "adversarial": self.load_adversarial_scenarios(),
        }
