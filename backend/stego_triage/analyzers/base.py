from typing import Dict, Any, List, Optional
import os
import time

class Analyzer:
    id: str = "base"
    name: str = "Base Analyzer"
    category: str = "misc"
    order: int = 100
    
    # Configuration
    quick: bool = False
    deep: bool = False
    needs_password: bool = False
    may_extract: bool = False
    timeout_secs: int = 60
    output_cap_bytes: int = 2 * 1024 * 1024
    
    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        """Override to check if this analyzer should run for the given file kind and tags."""
        return True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Override to implement actual analysis."""
        return self._no_result()
        
    def _create_result(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": "unsupported",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": 0,
            "summary": "",
            "findings": [],
            "artifacts": [],
            "log_artifact_id": None,
            "error": None,
            "truncated": False
        }
        
    def _no_result(self) -> Dict[str, Any]:
        res = self._create_result()
        res["status"] = "no_result"
        return res

_REGISTRY: List[Analyzer] = []

def register(analyzer_cls):
    _REGISTRY.append(analyzer_cls())
    # Sort by order
    _REGISTRY.sort(key=lambda a: a.order)
    return analyzer_cls

def get_analyzers() -> List[Analyzer]:
    return _REGISTRY
