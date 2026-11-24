"""Google Sheets access behind a small interface so the register logic can be tested without Google."""
from __future__ import annotations

from typing import Protocol

WORKBOOK_NAME = "Multi-Cloud-Operations-Control-Register"
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


class SheetsBackend(Protocol):
    def ensure_tabs(self, tabs: dict[str, list[str]]) -> None: ...
    def read_keys(self, tab: str) -> list[str]: ...
    def update_rows(self, tab: str, rows: dict[int, list], width: int) -> None: ...
    def append_rows(self, tab: str, rows: list[list]) -> None: ...


class GoogleSheetsBackend:
    """Uses the Sheets API with values written as RAW, so text taken from logs can never run as a formula."""

    def __init__(self, spreadsheet_id: str | None, credentials=None):
        from googleapiclient.discovery import build

        if credentials is None:
            import google.auth
            credentials, _ = google.auth.default(scopes=SCOPES)
        self.api = build("sheets", "v4", credentials=credentials, cache_discovery=False).spreadsheets()
        self.spreadsheet_id = spreadsheet_id or self.api.create(
            body={"properties": {"title": WORKBOOK_NAME}}, fields="spreadsheetId").execute()["spreadsheetId"]

    def ensure_tabs(self, tabs: dict[str, list[str]]) -> None:
        meta = self.api.get(spreadsheetId=self.spreadsheet_id, fields="sheets.properties.title").execute()
        existing = {s["properties"]["title"] for s in meta.get("sheets", [])}
        missing = [t for t in tabs if t not in existing]
        if missing:
            self.api.batchUpdate(spreadsheetId=self.spreadsheet_id, body={
                "requests": [{"addSheet": {"properties": {"title": t, "gridProperties": {"frozenRowCount": 1}}}} for t in missing]}).execute()
        # Header row is rewritten every sync; it covers automation-owned columns only.
        self.api.values().batchUpdate(spreadsheetId=self.spreadsheet_id, body={"valueInputOption": "RAW", "data": [
            {"range": f"'{t}'!A1:{col_letter(len(h))}1", "values": [h]} for t, h in tabs.items()]}).execute()

    def read_keys(self, tab: str) -> list[str]:
        resp = self.api.values().get(spreadsheetId=self.spreadsheet_id, range=f"'{tab}'!A2:A").execute()
        return [(r[0] if r else "") for r in resp.get("values", [])]

    def update_rows(self, tab: str, rows: dict[int, list], width: int) -> None:
        items = sorted(rows.items())
        for i in range(0, len(items), 500):
            self.api.values().batchUpdate(spreadsheetId=self.spreadsheet_id, body={"valueInputOption": "RAW", "data": [
                {"range": f"'{tab}'!A{n}:{col_letter(width)}{n}", "values": [v]} for n, v in items[i:i + 500]]}).execute()

    def append_rows(self, tab: str, rows: list[list]) -> None:
        for i in range(0, len(rows), 1000):
            self.api.values().append(spreadsheetId=self.spreadsheet_id, range=f"'{tab}'!A1", valueInputOption="RAW",
                                     insertDataOption="INSERT_ROWS", body={"values": rows[i:i + 1000]}).execute()


class MemorySheetsBackend:
    """In-memory stand-in used by tests."""

    def __init__(self):
        self.tabs: dict[str, list[list]] = {}

    def ensure_tabs(self, tabs):
        for t, h in tabs.items():
            rows = self.tabs.setdefault(t, [[]])
            rows[0] = list(h) + rows[0][len(h):]

    def read_keys(self, tab):
        return [(r[0] if r else "") for r in self.tabs[tab][1:]]

    def update_rows(self, tab, rows, width):
        for n, values in rows.items():
            current = self.tabs[tab][n - 1]
            self.tabs[tab][n - 1] = list(values) + current[width:]  # columns right of `width` belong to people

    def append_rows(self, tab, rows):
        self.tabs[tab].extend([list(r) for r in rows])
