# analysis/consensus.py
from __future__ import annotations
from typing import List, Dict
import difflib
from collections import defaultdict


class ConsensusEngine:
    def __init__(self, agreement_threshold: float = 0.7):
        self.agreement_threshold = agreement_threshold
        self.severity_buckets = {
            'low': (0.0, 3.9),
            'medium': (4.0, 6.9),
            'high': (7.0, 8.9),
            'critical': (9.0, 10.0)
        }

    def calculate_consensus(self, results: List[Dict]) -> Dict:
        """Core consensus algorithm without external dependencies"""
        if not results:
            return {'error': 'No valid analyses available'}

        consensus = results
        consensus['is_vulnerability'] = self._vote_boolean(results, 'is_vulnerability')
        consensus['cwe'] = self._vote_cwe(results)
        consensus['riskLevel'] = self._calculate_median_risk(results)
        consensus['fixCode'] =self._vote_fix(results)
        consensus['confidence'] = self._calculate_confidence(results)

        return consensus

    def _vote_boolean(self, results: List[Dict], key: str) -> bool:
        positives = sum(1 for r in results if r.get(key, False))
        return (positives / len(results)) >= self.agreement_threshold

    def _vote_cwe(self, results: List[Dict]) -> str:
        cwe_counts = defaultdict(int)
        for result in results:
            if cwe := result.get('cwe'):
                cwe_counts[cwe] += 1
        return max(cwe_counts, key=cwe_counts.get, default=None)

    def _calculate_median_risk(self, results: List[Dict]) -> float:
        risks = sorted(r.get('riskLevel', 0.0) for r in results)
        return risks[len(risks) // 2]

    def _vote_fix(self, results: List[Dict]) -> str:
        fix_scores = defaultdict(int)
        for result in results:
            fix = result.get('fixCode', '')
            fix_scores[fix] += 1
        return max(fix_scores, key=fix_scores.get, default='')

    def _calculate_confidence(self, results: List[Dict]) -> float:
        try:
            return min(
                self._vote_confidence('cwe', results),
                self._vote_confidence('fixCode', results)
            )
        except Exception as e:
            return 0.0

    def _vote_confidence(self, key: str, results: List[Dict]) -> float:
        counts = defaultdict(int)
        for result in results:
            counts[result.get(key)] += 1
        max_count = max(counts.values(), default=0)
        return max_count / len(results)