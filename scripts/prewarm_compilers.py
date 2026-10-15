"""Run at deploy/install time (with network), never at scan time: makes Aderyn's svm cache contain every
solc version that solc-select has installed, so sandboxed scans stay offline."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["CS_ALLOW_PREWARM"] = "1"
import scanner as S
for v in S.installed_solcs():
    S._prewarm_aderyn(v); print(v, "ok" if (S.SVM_DIR / v).exists() else "MISSING")
