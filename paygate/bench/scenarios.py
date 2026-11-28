"""
Scenario loader and validator for PayGate-Bench dataset (Benign, Adversarial, Dual Utility-Under-Attack).
"""

import os
import yaml
from typing import Dict, Any, List


class ScenarioLoader:
    """Loads Benign (25), Adversarial (25), and Dual Utility-Under-Attack (5) suites."""

    def __init__(
        self,
        benign_path: str = "paygate/bench/benign.yaml",
        adversarial_path: str = "paygate/bench/adversarial.yaml",
        dual_path: str = "paygate/bench/dual.yaml",
    ):
        self.benign_path = benign_path
        self.adversarial_path = adversarial_path
        self.dual_path = dual_path

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

    def load_dual_scenarios(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.dual_path):
            return []
        with open(self.dual_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("dual_tasks", [])

    def load_all_50_scenarios(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "benign": self.load_benign_scenarios(),
            "adversarial": self.load_adversarial_scenarios(),
            "dual": self.load_dual_scenarios(),
        }
