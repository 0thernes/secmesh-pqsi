# SPDX-License-Identifier: Apache-2.0
# Task runner for SecMesh-PQSI (https://github.com/casey/just)

default:
    @just --list

native:
    make -C native clean all test

node:
    node node/tests/test_secmesh_v2.mjs

lean:
    cd lean && lake build && lake env lean VerifyAxioms.lean

lean-checkers:
    cd lean && lake env leanchecker Solution && lake env leanchecker PalomarSolution && lake env leanchecker-paranoid Solution && lake env leanchecker-paranoid PalomarSolution

python:
    python python/secmesh_verify/exact_audit.py
    pytest python/tests/test_all.py -v
    python scripts/check_readme_axioms.py
    ruff check python scripts/check_citations.py scripts/check_readme_axioms.py
    mypy python/secmesh_verify scripts/check_citations.py scripts/check_readme_axioms.py --ignore-missing-imports
    python scripts/check_citations.py

papers:
    cd paper && tectonic -X compile main.tex --outdir build
    cd paper/engineering && tectonic -X compile secmesh_architecture.tex --outdir build

audit:
    bash scripts/audit-repo.sh

reproduce: native node lean python papers
    sha256sum -c MANIFEST.sha256

fuzz:
    clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -Inative/include -Inative/third_party/moonlab native/third_party/moonlab/crypto/sha3/sha3.c native/third_party/moonlab/crypto/aes/aes.c native/third_party/moonlab/crypto/drbg/ctr_drbg.c native/third_party/moonlab/crypto/mlkem/mlkem.c native/third_party/moonlab/crypto/mlkem/poly.c native/third_party/moonlab/applications/health_tests.c native/third_party/moonlab/applications/qrng_di.c native/src/secmesh_entropy.c native/src/secmesh_it_crypto.c native/src/secmesh_quantum_geo.c native/tests/fuzz_parsers.c -o /tmp/secmesh_fuzzer -lm
    /tmp/secmesh_fuzzer -max_total_time=30

rollback tag="v2.4.0":
    git checkout {{tag}} -- app/ dist/

all: native node lean python
