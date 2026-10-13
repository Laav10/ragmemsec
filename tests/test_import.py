"""Smoke test for the installed package."""


def test_import_ragmemsec():
    """The package can be imported after installation."""
    import ragmemsec

    assert ragmemsec.__name__ == "ragmemsec"
