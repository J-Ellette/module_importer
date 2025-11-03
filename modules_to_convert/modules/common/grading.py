"""
Grading system utilities for consistent scoring across modules.
"""

from typing import Dict, List, Tuple


class GradingSystem:
    """
    Provides standardized grading functionality for scanners.
    """
    
    # Grade thresholds
    GRADE_THRESHOLDS = {
        'A': 90,  # 90-100%
        'B': 80,  # 80-89%
        'C': 70,  # 70-79%
        'D': 60,  # 60-69%
        'F': 0    # 0-59%
    }
    
    # Grade descriptions
    GRADE_DESCRIPTIONS = {
        'A': 'Excellent - Exceeds standards with minimal issues',
        'B': 'Good - Meets standards with minor issues',
        'C': 'Satisfactory - Meets basic standards with some issues',
        'D': 'Below Average - Falls short of standards with significant issues',
        'F': 'Failing - Does not meet minimum standards'
    }
    
    @staticmethod
    def get_grade(score: float) -> str:
        """
        Convert a numeric score to a letter grade.
        
        Args:
            score: Numeric score (0-100)
            
        Returns:
            Letter grade (A, B, C, D, or F)
        """
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    @staticmethod
    def get_grade_description(grade: str) -> str:
        """
        Get the description for a letter grade.
        
        Args:
            grade: Letter grade (A, B, C, D, or F)
            
        Returns:
            Description of the grade
        """
        return GradingSystem.GRADE_DESCRIPTIONS.get(grade, 'Unknown grade')
    
    @staticmethod
    def calculate_weighted_score(components: Dict[str, Tuple[float, float]]) -> float:
        """
        Calculate a weighted score from multiple components.
        
        Args:
            components: Dictionary mapping component names to (score, weight) tuples
                       where score is 0-100 and weight is the relative importance
                       
        Returns:
            Weighted average score (0-100)
        """
        if not components:
            return 0.0
        
        total_weight = sum(weight for _, weight in components.values())
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(score * weight for score, weight in components.values())
        return weighted_sum / total_weight
    
    @staticmethod
    def get_grade_range(grade: str) -> Tuple[int, int]:
        """
        Get the score range for a letter grade.
        
        Args:
            grade: Letter grade (A, B, C, D, or F)
            
        Returns:
            Tuple of (min_score, max_score)
        """
        if grade == 'A':
            return (90, 100)
        elif grade == 'B':
            return (80, 89)
        elif grade == 'C':
            return (70, 79)
        elif grade == 'D':
            return (60, 69)
        else:  # F
            return (0, 59)
    
    @staticmethod
    def normalize_score(value: float, min_val: float, max_val: float) -> float:
        """
        Normalize a value to a 0-100 scale.
        
        Args:
            value: The value to normalize
            min_val: Minimum possible value
            max_val: Maximum possible value
            
        Returns:
            Normalized score (0-100)
        """
        if max_val == min_val:
            return 100.0 if value >= max_val else 0.0
        
        normalized = ((value - min_val) / (max_val - min_val)) * 100
        return max(0.0, min(100.0, normalized))
