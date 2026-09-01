import pytest
from tableau_dr.config import Config
from tableau_dr.exceptions import ConfigurationError

def test_config_missing_file():
    with pytest.raises(ConfigurationError):
        Config("non_existent_config.yaml")