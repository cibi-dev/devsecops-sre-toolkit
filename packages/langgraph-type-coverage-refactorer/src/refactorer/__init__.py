"""langgraph-type-coverage-refactorer package.

Multi-agent AST refactoring engine for strict MyPy typing and automated branch test coverage.
"""

from __future__ import annotations

from refactorer.graph import (
    create_refactorer_graph,
    evaluator_router,
    inspector_node,
    run_refactorer,
    run_refactorer_async,
)
from refactorer.inspector import (
    ASTInspector,
    InspectionError,
    safe_read_file,
)
from refactorer.nodes.annotator import (
    TypeAnnotator,
    annotator_node,
)
from refactorer.nodes.test_gen import (
    TestGenerator,
    test_gen_node,
)
from refactorer.nodes.verifier import (
    SandboxVerifier,
    verifier_node,
)
from refactorer.state import (
    MissingCoverageBranch,
    RefactorGraphState,
    RefactorProposal,
    RefactorState,
    TypeIssue,
    VerificationResult,
)

__version__ = "0.1.0"
__all__ = [
    "TypeIssue",
    "MissingCoverageBranch",
    "VerificationResult",
    "RefactorProposal",
    "RefactorState",
    "RefactorGraphState",
    "ASTInspector",
    "InspectionError",
    "safe_read_file",
    "TypeAnnotator",
    "annotator_node",
    "TestGenerator",
    "test_gen_node",
    "SandboxVerifier",
    "verifier_node",
    "create_refactorer_graph",
    "run_refactorer",
    "run_refactorer_async",
    "inspector_node",
    "evaluator_router",
]
