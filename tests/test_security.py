import tmppath
from pathlib import Path
from tableau_dr.security import sha256_file, validate_file

def test_sha256_computation(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("tableau-dr-test-payload")
    digest = sha256_file(test_file)
    assert len(digest) == 64
    assert validate_file(test_file, must_exist=True)