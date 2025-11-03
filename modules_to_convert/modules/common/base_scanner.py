"""
Base scanner class that all scanning modules inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from pathlib import Path
import json
from datetime import datetime


class BaseScanner(ABC):
    """
    Abstract base class for all code scanning modules.
    
    Each scanner must implement:
    - scan(): Perform the actual scanning
    - analyze(): Analyze the scan results
    - calculate_score(): Calculate the quality score (0-100)
    """
    
    def __init__(self, target_path: str):
        """
        Initialize the scanner.
        
        Args:
            target_path: Path to the repository or directory to scan
        """
        self.target_path = Path(target_path)
        self.scan_results: Dict[str, Any] = {}
        self.analysis: Dict[str, Any] = {}
        self.score: float = 0.0
        self.grade: str = ""
        self.scan_timestamp = datetime.now().isoformat()
        
        if not self.target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")
    
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Perform the scanning operation.
        
        Returns:
            Dictionary containing raw scan results
        """
        pass
    
    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze the scan results.
        
        Returns:
            Dictionary containing analysis results including:
            - strengths: List of positive findings
            - weaknesses: List of issues found
            - recommendations: List of improvement suggestions
        """
        pass
    
    @abstractmethod
    def calculate_score(self) -> float:
        """
        Calculate the quality score based on scan results.
        
        Returns:
            Score between 0.0 and 100.0
        """
        pass
    
    def run(self) -> Dict[str, Any]:
        """
        Run the complete scanning process: scan, analyze, and score.
        
        Returns:
            Complete results including score, grade, and analysis
        """
        self.scan_results = self.scan()
        self.analysis = self.analyze()
        self.score = self.calculate_score()
        self.grade = self._calculate_grade(self.score)
        
        return {
            'scanner': self.__class__.__name__,
            'target': str(self.target_path),
            'timestamp': self.scan_timestamp,
            'score': self.score,
            'grade': self.grade,
            'analysis': self.analysis,
            'raw_results': self.scan_results
        }
    
    def _calculate_grade(self, score: float) -> str:
        """
        Convert numeric score to letter grade.
        
        Args:
            score: Numeric score (0-100)
            
        Returns:
            Letter grade (F, D, C, B, A)
        """
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get the current results.
        
        Returns:
            Dictionary with all results
        """
        return {
            'scanner': self.__class__.__name__,
            'target': str(self.target_path),
            'timestamp': self.scan_timestamp,
            'score': self.score,
            'grade': self.grade,
            'analysis': self.analysis
        }
    
    def save_results(self, output_path: str) -> None:
        """
        Save results to a JSON file.
        
        Args:
            output_path: Path to save the results
        """
        results = self.get_results()
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
