"""
Report generation utilities for creating formatted scan reports.
"""

from typing import Dict, List, Any
from datetime import datetime
import json


class ReportGenerator:
    """
    Generates formatted reports from scanner results.
    """
    
    @staticmethod
    def generate_markdown_report(results: Dict[str, Any]) -> str:
        """
        Generate a markdown-formatted report.
        
        Args:
            results: Scanner results dictionary
            
        Returns:
            Markdown-formatted report string
        """
        report_lines = []
        
        # Header
        report_lines.append(f"# Code Scanning Report")
        report_lines.append(f"")
        report_lines.append(f"**Scanner:** {results.get('scanner', 'Unknown')}")
        report_lines.append(f"**Target:** {results.get('target', 'Unknown')}")
        report_lines.append(f"**Timestamp:** {results.get('timestamp', 'Unknown')}")
        report_lines.append(f"")
        
        # Score and Grade
        score = results.get('score', 0)
        grade = results.get('grade', 'F')
        report_lines.append(f"## Overall Assessment")
        report_lines.append(f"")
        report_lines.append(f"**Score:** {score:.1f}/100")
        report_lines.append(f"**Grade:** {grade}")
        report_lines.append(f"")
        
        # Analysis
        analysis = results.get('analysis', {})
        
        # Strengths
        strengths = analysis.get('strengths', [])
        if strengths:
            report_lines.append(f"## Strengths")
            report_lines.append(f"")
            for strength in strengths:
                report_lines.append(f"- {strength}")
            report_lines.append(f"")
        
        # Weaknesses
        weaknesses = analysis.get('weaknesses', [])
        if weaknesses:
            report_lines.append(f"## Weaknesses")
            report_lines.append(f"")
            for weakness in weaknesses:
                report_lines.append(f"- {weakness}")
            report_lines.append(f"")
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            report_lines.append(f"## Recommendations")
            report_lines.append(f"")
            for i, recommendation in enumerate(recommendations, 1):
                report_lines.append(f"{i}. {recommendation}")
            report_lines.append(f"")
        
        # Summary statistics
        summary = analysis.get('summary', {})
        if summary:
            report_lines.append(f"## Summary Statistics")
            report_lines.append(f"")
            for key, value in summary.items():
                report_lines.append(f"- **{key}:** {value}")
            report_lines.append(f"")
        
        return "\n".join(report_lines)
    
    @staticmethod
    def generate_json_report(results: Dict[str, Any], indent: int = 2) -> str:
        """
        Generate a JSON-formatted report.
        
        Args:
            results: Scanner results dictionary
            indent: Number of spaces for indentation
            
        Returns:
            JSON-formatted report string
        """
        return json.dumps(results, indent=indent)
    
    @staticmethod
    def generate_text_report(results: Dict[str, Any]) -> str:
        """
        Generate a plain text report.
        
        Args:
            results: Scanner results dictionary
            
        Returns:
            Plain text report string
        """
        report_lines = []
        
        # Header
        report_lines.append("=" * 70)
        report_lines.append("CODE SCANNING REPORT")
        report_lines.append("=" * 70)
        report_lines.append("")
        report_lines.append(f"Scanner:   {results.get('scanner', 'Unknown')}")
        report_lines.append(f"Target:    {results.get('target', 'Unknown')}")
        report_lines.append(f"Timestamp: {results.get('timestamp', 'Unknown')}")
        report_lines.append("")
        
        # Score and Grade
        score = results.get('score', 0)
        grade = results.get('grade', 'F')
        report_lines.append("-" * 70)
        report_lines.append("OVERALL ASSESSMENT")
        report_lines.append("-" * 70)
        report_lines.append(f"Score: {score:.1f}/100")
        report_lines.append(f"Grade: {grade}")
        report_lines.append("")
        
        # Analysis
        analysis = results.get('analysis', {})
        
        # Strengths
        strengths = analysis.get('strengths', [])
        if strengths:
            report_lines.append("-" * 70)
            report_lines.append("STRENGTHS")
            report_lines.append("-" * 70)
            for strength in strengths:
                report_lines.append(f"  * {strength}")
            report_lines.append("")
        
        # Weaknesses
        weaknesses = analysis.get('weaknesses', [])
        if weaknesses:
            report_lines.append("-" * 70)
            report_lines.append("WEAKNESSES")
            report_lines.append("-" * 70)
            for weakness in weaknesses:
                report_lines.append(f"  * {weakness}")
            report_lines.append("")
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            report_lines.append("-" * 70)
            report_lines.append("RECOMMENDATIONS")
            report_lines.append("-" * 70)
            for i, recommendation in enumerate(recommendations, 1):
                report_lines.append(f"  {i}. {recommendation}")
            report_lines.append("")
        
        # Summary statistics
        summary = analysis.get('summary', {})
        if summary:
            report_lines.append("-" * 70)
            report_lines.append("SUMMARY STATISTICS")
            report_lines.append("-" * 70)
            for key, value in summary.items():
                report_lines.append(f"  {key}: {value}")
            report_lines.append("")
        
        report_lines.append("=" * 70)
        
        return "\n".join(report_lines)
    
    @staticmethod
    def save_report(results: Dict[str, Any], output_path: str, format: str = 'markdown') -> None:
        """
        Save a report to a file.
        
        Args:
            results: Scanner results dictionary
            output_path: Path to save the report
            format: Report format ('markdown', 'json', or 'text')
        """
        if format == 'markdown':
            content = ReportGenerator.generate_markdown_report(results)
        elif format == 'json':
            content = ReportGenerator.generate_json_report(results)
        elif format == 'text':
            content = ReportGenerator.generate_text_report(results)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        with open(output_path, 'w') as f:
            f.write(content)
