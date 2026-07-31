from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_landing_page_files_exist():
    assert (ROOT / "docs" / "index.html").is_file()
    assert (ROOT / "docs" / "assets" / "site.css").is_file()


def test_landing_page_mentions_core_contracts():
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    for expected in (
        "Discover → review → apply",
        "users_report.xlsx",
        "users_plan.json",
        "users_results.json",
        "Never deletes accounts",
        "Never touched",
        "linux-users",
        "RHEL 9 fleet operations",
    ):
        assert expected in page
