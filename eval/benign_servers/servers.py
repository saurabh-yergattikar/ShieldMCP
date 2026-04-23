"""25 benign MCP server classes for false-positive testing.

Each server provides legitimate tool functionality with clean descriptions.
Some descriptions deliberately use strong language ("must", "always", "required")
in legitimate contexts to stress-test false-positive detection.
"""

from __future__ import annotations

from typing import Any

from .base import BenignMCPServer


def _text(t: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": t}]}


def _schema(props: dict, required: list[str] | None = None) -> dict:
    s: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        s["required"] = required
    return s


# ---------------------------------------------------------------------------
# 1. FileSystem
# ---------------------------------------------------------------------------
class FileSystemServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-filesystem", "filesystem")

    def get_tools(self):
        return [
            {
                "name": "read_file",
                "description": (
                    "Reads the contents of a file at the given path. The path parameter "
                    "must be an absolute path. Returns the raw text content of the file. "
                    "Binary files are not supported and will always produce an error."
                ),
                "inputSchema": _schema(
                    {"path": {"type": "string", "description": "Absolute path to the file to read"}},
                    ["path"],
                ),
            },
            {
                "name": "write_file",
                "description": "Writes text content to a file. Creates parent directories if they do not exist.",
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Absolute path to the file"},
                        "content": {"type": "string", "description": "Text content to write"},
                    },
                    ["path", "content"],
                ),
            },
            {
                "name": "list_dir",
                "description": "Lists files and directories in the specified directory path. Returns names and types.",
                "inputSchema": _schema(
                    {"path": {"type": "string", "description": "Directory path to list"}},
                    ["path"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        path = arguments.get("path", "/tmp")
        if tool_name == "read_file":
            return _text(f"Contents of {path}:\nHello, world!\nLine 2 of the file.")
        if tool_name == "write_file":
            return _text(f"Successfully wrote {len(arguments.get('content', ''))} bytes to {path}")
        if tool_name == "list_dir":
            return _text(f"Directory listing for {path}:\n  file1.txt (file)\n  docs/ (dir)\n  README.md (file)")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 2. SQLiteDB
# ---------------------------------------------------------------------------
class SQLiteDBServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-sqlite", "database")

    def get_tools(self):
        return [
            {
                "name": "query",
                "description": (
                    "Executes a read-only SQL query against the SQLite database and returns "
                    "rows as JSON. The query must be a SELECT statement; write operations are "
                    "rejected. Always returns at most 1000 rows to prevent memory issues."
                ),
                "inputSchema": _schema({"sql": {"type": "string", "description": "SQL SELECT query"}}, ["sql"]),
            },
            {
                "name": "insert",
                "description": "Inserts a row into the specified table. Returns the new row ID.",
                "inputSchema": _schema(
                    {
                        "table": {"type": "string", "description": "Table name"},
                        "values": {"type": "object", "description": "Column-value pairs to insert"},
                    },
                    ["table", "values"],
                ),
            },
            {
                "name": "create_table",
                "description": "Creates a new table with the given schema definition. Table names are required to be alphanumeric.",
                "inputSchema": _schema(
                    {
                        "table": {"type": "string", "description": "Table name"},
                        "columns": {"type": "object", "description": "Column definitions mapping name to type"},
                    },
                    ["table", "columns"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "query":
            return _text('[{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]')
        if tool_name == "insert":
            return _text(f"Inserted row into {arguments.get('table', 'unknown')} with id=42")
        if tool_name == "create_table":
            return _text(f"Table '{arguments.get('table', 'unknown')}' created successfully")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 3. WebSearch
# ---------------------------------------------------------------------------
class WebSearchServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-websearch", "search")

    def get_tools(self):
        return [
            {
                "name": "search",
                "description": (
                    "Searches the web using the provided query string and returns the top results. "
                    "Each result includes a title, URL, and snippet. You must provide a non-empty "
                    "query. Results are always ranked by relevance."
                ),
                "inputSchema": _schema(
                    {
                        "query": {"type": "string", "description": "Search query string"},
                        "num_results": {"type": "integer", "description": "Number of results (default 10)"},
                    },
                    ["query"],
                ),
            },
            {
                "name": "get_page",
                "description": "Fetches and returns the text content of a web page at the given URL.",
                "inputSchema": _schema({"url": {"type": "string", "description": "URL of the page to fetch"}}, ["url"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "search":
            q = arguments.get("query", "")
            return _text(
                f'Search results for "{q}":\n'
                "1. Example Result - https://example.com - A relevant snippet.\n"
                "2. Another Page - https://example.org - More information here."
            )
        if tool_name == "get_page":
            return _text(f"Page content from {arguments.get('url', '')}:\n<p>Welcome to Example.</p>")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 4. CodeExecution
# ---------------------------------------------------------------------------
class CodeExecutionServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-code-execution", "code")

    def get_tools(self):
        return [
            {
                "name": "run_python",
                "description": (
                    "Executes Python code in a sandboxed environment and returns stdout/stderr. "
                    "The sandbox has no network access. Execution is always terminated after a "
                    "30-second timeout. The code parameter is required."
                ),
                "inputSchema": _schema({"code": {"type": "string", "description": "Python source code to execute"}}, ["code"]),
            },
            {
                "name": "run_javascript",
                "description": "Runs JavaScript code in a Node.js sandbox. Returns the captured output.",
                "inputSchema": _schema({"code": {"type": "string", "description": "JavaScript source code"}}, ["code"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "run_python":
            return _text("stdout: 42\nstderr: (none)\nexit_code: 0")
        if tool_name == "run_javascript":
            return _text("stdout: hello world\nstderr: (none)\nexit_code: 0")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 5. Calendar
# ---------------------------------------------------------------------------
class CalendarServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-calendar", "calendar")

    def get_tools(self):
        return [
            {
                "name": "get_events",
                "description": "Retrieves calendar events for the given date range. Returns a list of events with title, time, and location.",
                "inputSchema": _schema(
                    {
                        "start_date": {"type": "string", "description": "Start date in YYYY-MM-DD format"},
                        "end_date": {"type": "string", "description": "End date in YYYY-MM-DD format"},
                    },
                    ["start_date"],
                ),
            },
            {
                "name": "create_event",
                "description": (
                    "Creates a new calendar event. The title and start_time fields are required. "
                    "Duration defaults to 60 minutes if not specified."
                ),
                "inputSchema": _schema(
                    {
                        "title": {"type": "string", "description": "Event title"},
                        "start_time": {"type": "string", "description": "ISO 8601 datetime"},
                        "duration_minutes": {"type": "integer", "description": "Duration in minutes"},
                    },
                    ["title", "start_time"],
                ),
            },
            {
                "name": "delete_event",
                "description": "Deletes a calendar event by its unique event ID.",
                "inputSchema": _schema({"event_id": {"type": "string", "description": "Unique event identifier"}}, ["event_id"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "get_events":
            return _text(
                '[{"title": "Team standup", "time": "09:00", "location": "Room 3B"}, '
                '{"title": "Lunch with Alex", "time": "12:30", "location": "Cafe"}]'
            )
        if tool_name == "create_event":
            return _text(f"Event '{arguments.get('title', '')}' created with id=evt-1234")
        if tool_name == "delete_event":
            return _text(f"Event {arguments.get('event_id', '')} deleted")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 6. Email
# ---------------------------------------------------------------------------
class EmailServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-email", "email")

    def get_tools(self):
        return [
            {
                "name": "send_email",
                "description": (
                    "Sends an email to the specified recipient. The 'to' field must be a valid "
                    "email address. The subject and body parameters are always required. Attachments "
                    "are optional and must reference files by path."
                ),
                "inputSchema": _schema(
                    {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject line"},
                        "body": {"type": "string", "description": "Email body text"},
                    },
                    ["to", "subject", "body"],
                ),
            },
            {
                "name": "read_inbox",
                "description": "Returns the most recent emails from the user's inbox. Defaults to the last 20 messages.",
                "inputSchema": _schema({"limit": {"type": "integer", "description": "Max emails to return"}}),
            },
            {
                "name": "search_emails",
                "description": "Searches emails by keyword across subject and body fields. Returns matching messages.",
                "inputSchema": _schema({"query": {"type": "string", "description": "Search keyword"}}, ["query"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "send_email":
            return _text(f"Email sent to {arguments.get('to', '')} with subject '{arguments.get('subject', '')}'")
        if tool_name == "read_inbox":
            return _text(
                '[{"from": "alice@example.com", "subject": "Meeting notes", "date": "2025-01-15"}, '
                '{"from": "bob@example.com", "subject": "Project update", "date": "2025-01-14"}]'
            )
        if tool_name == "search_emails":
            return _text(f'Found 3 emails matching "{arguments.get("query", "")}"')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 7. Weather
# ---------------------------------------------------------------------------
class WeatherServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-weather", "weather")

    def get_tools(self):
        return [
            {
                "name": "get_weather",
                "description": (
                    "Returns the current weather conditions for a location. The location parameter "
                    "is required and must be a city name or coordinates. Temperature is always "
                    "returned in both Celsius and Fahrenheit."
                ),
                "inputSchema": _schema({"location": {"type": "string", "description": "City name or lat,lon"}}, ["location"]),
            },
            {
                "name": "get_forecast",
                "description": "Returns a multi-day weather forecast. Defaults to 5 days if days is not specified.",
                "inputSchema": _schema(
                    {
                        "location": {"type": "string", "description": "City name or lat,lon"},
                        "days": {"type": "integer", "description": "Number of forecast days"},
                    },
                    ["location"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        loc = arguments.get("location", "Unknown")
        if tool_name == "get_weather":
            return _text(f'{{"location": "{loc}", "temp_c": 22, "temp_f": 72, "condition": "Partly cloudy", "humidity": 55}}')
        if tool_name == "get_forecast":
            return _text(f'{{"location": "{loc}", "forecast": [{{"day": "Mon", "high": 24, "low": 15}}, {{"day": "Tue", "high": 21, "low": 13}}]}}')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 8. Calculator
# ---------------------------------------------------------------------------
class CalculatorServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-calculator", "math")

    def get_tools(self):
        return [
            {
                "name": "calculate",
                "description": (
                    "Evaluates a mathematical expression and returns the result. Supports "
                    "arithmetic, trigonometric, and logarithmic functions. The expression must "
                    "be a valid mathematical expression string."
                ),
                "inputSchema": _schema({"expression": {"type": "string", "description": "Math expression (e.g. '2+2', 'sin(pi/4)')"}}, ["expression"]),
            },
            {
                "name": "convert_units",
                "description": "Converts a value from one unit to another. Supported categories include length, weight, temperature, and volume.",
                "inputSchema": _schema(
                    {
                        "value": {"type": "number", "description": "Numeric value to convert"},
                        "from_unit": {"type": "string", "description": "Source unit"},
                        "to_unit": {"type": "string", "description": "Target unit"},
                    },
                    ["value", "from_unit", "to_unit"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "calculate":
            return _text(f"Result: 42")
        if tool_name == "convert_units":
            return _text(f"{arguments.get('value', 0)} {arguments.get('from_unit', '')} = 3.28 {arguments.get('to_unit', '')}")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 9. NoteTaking
# ---------------------------------------------------------------------------
class NoteTakingServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-notes", "notes")

    def get_tools(self):
        return [
            {
                "name": "create_note",
                "description": "Creates a new note with the given title and body. The title is required and must be non-empty.",
                "inputSchema": _schema(
                    {
                        "title": {"type": "string", "description": "Note title"},
                        "body": {"type": "string", "description": "Note content in plain text or Markdown"},
                    },
                    ["title"],
                ),
            },
            {
                "name": "list_notes",
                "description": "Lists all saved notes sorted by last-modified date. Returns titles and IDs.",
                "inputSchema": _schema({"limit": {"type": "integer", "description": "Max notes to return"}}),
            },
            {
                "name": "search_notes",
                "description": "Performs a full-text search across all notes. Returns matching notes with highlighted snippets.",
                "inputSchema": _schema({"query": {"type": "string", "description": "Search query"}}, ["query"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "create_note":
            return _text(f"Note '{arguments.get('title', '')}' created with id=note-567")
        if tool_name == "list_notes":
            return _text('[{"id": "note-1", "title": "Shopping list"}, {"id": "note-2", "title": "Project ideas"}]')
        if tool_name == "search_notes":
            return _text(f'Found 2 notes matching "{arguments.get("query", "")}"')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 10. JSONStore
# ---------------------------------------------------------------------------
class JSONStoreServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-jsonstore", "storage")

    def get_tools(self):
        return [
            {
                "name": "get",
                "description": "Retrieves a JSON value by key. Returns null if the key does not exist.",
                "inputSchema": _schema({"key": {"type": "string", "description": "Storage key"}}, ["key"]),
            },
            {
                "name": "set",
                "description": (
                    "Stores a JSON value under the specified key. The value parameter must be "
                    "valid JSON. Overwrites any existing value for that key."
                ),
                "inputSchema": _schema(
                    {
                        "key": {"type": "string", "description": "Storage key"},
                        "value": {"type": "object", "description": "JSON value to store"},
                    },
                    ["key", "value"],
                ),
            },
            {
                "name": "delete",
                "description": "Removes the entry for the given key. No-op if the key does not exist.",
                "inputSchema": _schema({"key": {"type": "string", "description": "Key to delete"}}, ["key"]),
            },
            {
                "name": "list_keys",
                "description": "Lists all keys currently stored in the JSON store.",
                "inputSchema": _schema({}),
            },
        ]

    def handle_call(self, tool_name, arguments):
        key = arguments.get("key", "mykey")
        if tool_name == "get":
            return _text(f'{{"key": "{key}", "value": {{"status": "active", "count": 7}}}}')
        if tool_name == "set":
            return _text(f"Stored value under key '{key}'")
        if tool_name == "delete":
            return _text(f"Deleted key '{key}'")
        if tool_name == "list_keys":
            return _text('["config", "user_prefs", "session_data"]')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 11. KeyValueStore
# ---------------------------------------------------------------------------
class KeyValueStoreServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-kvstore", "storage")

    def get_tools(self):
        return [
            {
                "name": "get",
                "description": "Gets the string value associated with the given key. Returns an empty string if not found.",
                "inputSchema": _schema({"key": {"type": "string", "description": "Key to look up"}}, ["key"]),
            },
            {
                "name": "set",
                "description": "Sets a string value for the given key. Both key and value are required and must be strings.",
                "inputSchema": _schema(
                    {
                        "key": {"type": "string", "description": "Key"},
                        "value": {"type": "string", "description": "Value to store"},
                    },
                    ["key", "value"],
                ),
            },
            {
                "name": "delete",
                "description": "Deletes the key-value pair for the specified key.",
                "inputSchema": _schema({"key": {"type": "string", "description": "Key to delete"}}, ["key"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        key = arguments.get("key", "k")
        if tool_name == "get":
            return _text(f"Value for '{key}': some_stored_value")
        if tool_name == "set":
            return _text(f"Set '{key}' = '{arguments.get('value', '')}'")
        if tool_name == "delete":
            return _text(f"Deleted '{key}'")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 12. GitOperations
# ---------------------------------------------------------------------------
class GitOperationsServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-git", "git")

    def get_tools(self):
        return [
            {
                "name": "status",
                "description": (
                    "Returns the current git status of the repository including modified, staged, "
                    "and untracked files. The repo_path parameter must point to a valid git repository."
                ),
                "inputSchema": _schema({"repo_path": {"type": "string", "description": "Path to the git repository"}}, ["repo_path"]),
            },
            {
                "name": "log",
                "description": "Shows recent git commit history. Defaults to the last 10 commits.",
                "inputSchema": _schema(
                    {
                        "repo_path": {"type": "string", "description": "Repository path"},
                        "count": {"type": "integer", "description": "Number of commits to show"},
                    },
                    ["repo_path"],
                ),
            },
            {
                "name": "diff",
                "description": "Shows the diff for uncommitted changes or between two refs.",
                "inputSchema": _schema(
                    {
                        "repo_path": {"type": "string", "description": "Repository path"},
                        "ref": {"type": "string", "description": "Optional ref to diff against"},
                    },
                    ["repo_path"],
                ),
            },
            {
                "name": "commit",
                "description": "Creates a git commit with all staged changes. A commit message is always required.",
                "inputSchema": _schema(
                    {
                        "repo_path": {"type": "string", "description": "Repository path"},
                        "message": {"type": "string", "description": "Commit message"},
                    },
                    ["repo_path", "message"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "status":
            return _text("On branch main\nChanges not staged:\n  modified: src/app.py\nUntracked:\n  notes.txt")
        if tool_name == "log":
            return _text("abc1234 Fix typo in README (2 hours ago)\ndef5678 Add user auth (1 day ago)")
        if tool_name == "diff":
            return _text("diff --git a/src/app.py\n- old line\n+ new line")
        if tool_name == "commit":
            return _text(f"[main abc9999] {arguments.get('message', '')}\n 1 file changed")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 13. HTTPClient
# ---------------------------------------------------------------------------
class HTTPClientServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-http", "http")

    def get_tools(self):
        return [
            {
                "name": "get",
                "description": (
                    "Performs an HTTP GET request to the specified URL. Returns status code, "
                    "headers, and response body. The URL must be a fully-qualified URL starting "
                    "with http:// or https://."
                ),
                "inputSchema": _schema({"url": {"type": "string", "description": "Target URL"}}, ["url"]),
            },
            {
                "name": "post",
                "description": "Sends an HTTP POST request with a JSON body. Returns the response status and body.",
                "inputSchema": _schema(
                    {
                        "url": {"type": "string", "description": "Target URL"},
                        "body": {"type": "object", "description": "JSON request body"},
                    },
                    ["url", "body"],
                ),
            },
            {
                "name": "put",
                "description": "Sends an HTTP PUT request. Used to update existing resources.",
                "inputSchema": _schema(
                    {
                        "url": {"type": "string", "description": "Target URL"},
                        "body": {"type": "object", "description": "JSON request body"},
                    },
                    ["url", "body"],
                ),
            },
            {
                "name": "delete",
                "description": "Sends an HTTP DELETE request to remove a resource at the given URL.",
                "inputSchema": _schema({"url": {"type": "string", "description": "Target URL"}}, ["url"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        url = arguments.get("url", "https://example.com")
        if tool_name == "get":
            return _text(f'{{"status": 200, "url": "{url}", "body": "{{\\"message\\": \\"ok\\"}}"}}')
        if tool_name == "post":
            return _text(f'{{"status": 201, "url": "{url}", "body": "{{\\"id\\": 1}}"}}')
        if tool_name == "put":
            return _text(f'{{"status": 200, "url": "{url}", "body": "{{\\"updated\\": true}}"}}')
        if tool_name == "delete":
            return _text(f'{{"status": 204, "url": "{url}"}}')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 14. TextProcessor
# ---------------------------------------------------------------------------
class TextProcessorServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-textprocessor", "nlp")

    def get_tools(self):
        return [
            {
                "name": "summarize",
                "description": (
                    "Generates a concise summary of the provided text. The text parameter is "
                    "required and should contain the full document to summarize. Maximum input "
                    "length is 100,000 characters."
                ),
                "inputSchema": _schema(
                    {
                        "text": {"type": "string", "description": "Text to summarize"},
                        "max_sentences": {"type": "integer", "description": "Maximum sentences in summary"},
                    },
                    ["text"],
                ),
            },
            {
                "name": "translate",
                "description": "Translates text from one language to another. Language codes must follow ISO 639-1 format.",
                "inputSchema": _schema(
                    {
                        "text": {"type": "string", "description": "Text to translate"},
                        "source_lang": {"type": "string", "description": "Source language code"},
                        "target_lang": {"type": "string", "description": "Target language code"},
                    },
                    ["text", "target_lang"],
                ),
            },
            {
                "name": "extract_entities",
                "description": "Extracts named entities (people, places, organizations, dates) from the given text.",
                "inputSchema": _schema({"text": {"type": "string", "description": "Input text"}}, ["text"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "summarize":
            return _text("Summary: The document discusses key project milestones and upcoming deadlines.")
        if tool_name == "translate":
            return _text(f"Translation ({arguments.get('target_lang', 'en')}): Bonjour le monde")
        if tool_name == "extract_entities":
            return _text('[{"entity": "Alice", "type": "PERSON"}, {"entity": "Acme Corp", "type": "ORG"}]')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 15. ImageMetadata
# ---------------------------------------------------------------------------
class ImageMetadataServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-image-metadata", "media")

    def get_tools(self):
        return [
            {
                "name": "get_info",
                "description": "Returns basic image information: dimensions, format, color space, and file size. The path must point to a valid image file.",
                "inputSchema": _schema({"path": {"type": "string", "description": "Path to image file"}}, ["path"]),
            },
            {
                "name": "get_exif",
                "description": "Extracts EXIF metadata from the image including camera model, exposure, GPS coordinates if available.",
                "inputSchema": _schema({"path": {"type": "string", "description": "Path to image file"}}, ["path"]),
            },
            {
                "name": "resize",
                "description": (
                    "Resizes an image to the specified dimensions. At least one of width or height "
                    "is required. Aspect ratio is preserved by default unless both are provided."
                ),
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Path to image file"},
                        "width": {"type": "integer", "description": "Target width in pixels"},
                        "height": {"type": "integer", "description": "Target height in pixels"},
                    },
                    ["path"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        path = arguments.get("path", "image.jpg")
        if tool_name == "get_info":
            return _text(f'{{"path": "{path}", "width": 1920, "height": 1080, "format": "JPEG", "size_kb": 340}}')
        if tool_name == "get_exif":
            return _text(f'{{"camera": "Canon EOS R5", "exposure": "1/250", "iso": 400, "gps": null}}')
        if tool_name == "resize":
            return _text(f"Resized {path} to {arguments.get('width', 800)}x{arguments.get('height', 600)}")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 16. PDFReader
# ---------------------------------------------------------------------------
class PDFReaderServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-pdf", "documents")

    def get_tools(self):
        return [
            {
                "name": "extract_text",
                "description": (
                    "Extracts all text content from a PDF file. The file path is required and "
                    "must point to a valid PDF document. Returns plain text with page breaks indicated."
                ),
                "inputSchema": _schema({"path": {"type": "string", "description": "Path to the PDF file"}}, ["path"]),
            },
            {
                "name": "get_metadata",
                "description": "Returns PDF metadata: title, author, creation date, page count, and PDF version.",
                "inputSchema": _schema({"path": {"type": "string", "description": "Path to the PDF file"}}, ["path"]),
            },
            {
                "name": "get_pages",
                "description": "Returns text content for a specific range of pages. Page numbers are 1-indexed.",
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Path to PDF"},
                        "start_page": {"type": "integer", "description": "First page (1-indexed)"},
                        "end_page": {"type": "integer", "description": "Last page (inclusive)"},
                    },
                    ["path", "start_page", "end_page"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        path = arguments.get("path", "doc.pdf")
        if tool_name == "extract_text":
            return _text(f"Text from {path}:\nPage 1: Introduction to the quarterly report...\nPage 2: Financial summary...")
        if tool_name == "get_metadata":
            return _text(f'{{"title": "Q4 Report", "author": "Finance Team", "pages": 24, "created": "2025-01-10"}}')
        if tool_name == "get_pages":
            return _text(f"Pages {arguments.get('start_page', 1)}-{arguments.get('end_page', 1)}: Content here...")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 17. CSVProcessor
# ---------------------------------------------------------------------------
class CSVProcessorServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-csv", "data")

    def get_tools(self):
        return [
            {
                "name": "read_csv",
                "description": (
                    "Reads a CSV file and returns the data as a list of row objects. The path "
                    "parameter is required. The delimiter defaults to comma but can be overridden. "
                    "Always reads the first row as column headers."
                ),
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Path to CSV file"},
                        "delimiter": {"type": "string", "description": "Column delimiter character"},
                    },
                    ["path"],
                ),
            },
            {
                "name": "filter_rows",
                "description": "Filters CSV rows where the specified column matches the given value.",
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Path to CSV file"},
                        "column": {"type": "string", "description": "Column name to filter on"},
                        "value": {"type": "string", "description": "Value to match"},
                    },
                    ["path", "column", "value"],
                ),
            },
            {
                "name": "aggregate",
                "description": "Computes aggregate statistics (sum, mean, min, max, count) for a numeric column.",
                "inputSchema": _schema(
                    {
                        "path": {"type": "string", "description": "Path to CSV file"},
                        "column": {"type": "string", "description": "Column to aggregate"},
                        "operation": {"type": "string", "description": "One of: sum, mean, min, max, count"},
                    },
                    ["path", "column", "operation"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "read_csv":
            return _text('[{"name": "Alice", "age": 30, "city": "NYC"}, {"name": "Bob", "age": 25, "city": "LA"}]')
        if tool_name == "filter_rows":
            return _text(f'Filtered rows where {arguments.get("column", "")} = {arguments.get("value", "")}: 5 rows')
        if tool_name == "aggregate":
            return _text(f'{arguments.get("operation", "sum")}({arguments.get("column", "")}): 1234.56')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 18. MarkdownRenderer
# ---------------------------------------------------------------------------
class MarkdownRendererServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-markdown", "rendering")

    def get_tools(self):
        return [
            {
                "name": "render",
                "description": "Renders Markdown text to a formatted preview. Returns a text-based rendering of the document structure.",
                "inputSchema": _schema({"markdown": {"type": "string", "description": "Markdown source text"}}, ["markdown"]),
            },
            {
                "name": "to_html",
                "description": (
                    "Converts Markdown to HTML. Supports GitHub-Flavored Markdown extensions "
                    "including tables, task lists, and fenced code blocks. Input is required."
                ),
                "inputSchema": _schema({"markdown": {"type": "string", "description": "Markdown source text"}}, ["markdown"]),
            },
            {
                "name": "to_pdf",
                "description": "Converts Markdown to a PDF file. The output_path parameter specifies where to save the PDF.",
                "inputSchema": _schema(
                    {
                        "markdown": {"type": "string", "description": "Markdown source text"},
                        "output_path": {"type": "string", "description": "Path for the output PDF"},
                    },
                    ["markdown", "output_path"],
                ),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "render":
            return _text("Rendered preview:\n# Title\nParagraph text with **bold** emphasis.")
        if tool_name == "to_html":
            return _text("<h1>Title</h1>\n<p>Paragraph text with <strong>bold</strong> emphasis.</p>")
        if tool_name == "to_pdf":
            return _text(f"PDF saved to {arguments.get('output_path', 'output.pdf')}")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 19. PasswordGenerator
# ---------------------------------------------------------------------------
class PasswordGeneratorServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-password", "security")

    def get_tools(self):
        return [
            {
                "name": "generate",
                "description": (
                    "Generates a cryptographically secure random password. Length must be between "
                    "8 and 128 characters. By default, passwords always include uppercase, lowercase, "
                    "digits, and special characters."
                ),
                "inputSchema": _schema(
                    {
                        "length": {"type": "integer", "description": "Password length (8-128)"},
                        "exclude_symbols": {"type": "boolean", "description": "Exclude special characters"},
                    },
                ),
            },
            {
                "name": "check_strength",
                "description": "Evaluates password strength and returns a score from 0 (very weak) to 100 (very strong) with feedback.",
                "inputSchema": _schema({"password": {"type": "string", "description": "Password to evaluate"}}, ["password"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "generate":
            length = arguments.get("length", 16)
            return _text(f"Generated password ({length} chars): xK9#mP2!qR5@nL7$")
        if tool_name == "check_strength":
            return _text('{"score": 85, "strength": "strong", "feedback": "Good length and character variety"}')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 20. TimeZone
# ---------------------------------------------------------------------------
class TimeZoneServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-timezone", "time")

    def get_tools(self):
        return [
            {
                "name": "convert",
                "description": (
                    "Converts a datetime from one timezone to another. The datetime string must "
                    "be in ISO 8601 format. Both source and target timezone parameters are required "
                    "and must be valid IANA timezone identifiers."
                ),
                "inputSchema": _schema(
                    {
                        "datetime": {"type": "string", "description": "ISO 8601 datetime string"},
                        "from_tz": {"type": "string", "description": "Source IANA timezone"},
                        "to_tz": {"type": "string", "description": "Target IANA timezone"},
                    },
                    ["datetime", "from_tz", "to_tz"],
                ),
            },
            {
                "name": "list_zones",
                "description": "Lists all available IANA timezone identifiers, optionally filtered by region.",
                "inputSchema": _schema({"region": {"type": "string", "description": "Optional region filter (e.g. 'America', 'Europe')"}}),
            },
            {
                "name": "get_current",
                "description": "Returns the current date and time in the specified timezone.",
                "inputSchema": _schema({"timezone": {"type": "string", "description": "IANA timezone identifier"}}, ["timezone"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "convert":
            return _text(f"2025-01-15T09:00:00 {arguments.get('from_tz', 'UTC')} = 2025-01-15T17:00:00 {arguments.get('to_tz', 'UTC')}")
        if tool_name == "list_zones":
            region = arguments.get("region", "")
            return _text(f'Timezones{f" in {region}" if region else ""}: ["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"]')
        if tool_name == "get_current":
            return _text(f"Current time in {arguments.get('timezone', 'UTC')}: 2025-01-15T14:30:00")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 21. URLShortener
# ---------------------------------------------------------------------------
class URLShortenerServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-urlshortener", "web")

    def get_tools(self):
        return [
            {
                "name": "shorten",
                "description": "Creates a shortened URL for the given long URL. The URL must be a valid HTTP or HTTPS URL.",
                "inputSchema": _schema({"url": {"type": "string", "description": "Long URL to shorten"}}, ["url"]),
            },
            {
                "name": "expand",
                "description": "Expands a shortened URL to its original long form. Returns the target URL and redirect chain.",
                "inputSchema": _schema({"short_url": {"type": "string", "description": "Shortened URL to expand"}}, ["short_url"]),
            },
            {
                "name": "get_stats",
                "description": "Returns click statistics for a shortened URL including total clicks, referrers, and geographic distribution.",
                "inputSchema": _schema({"short_url": {"type": "string", "description": "Shortened URL"}}, ["short_url"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "shorten":
            return _text(f'{{"short_url": "https://sho.rt/abc123", "original": "{arguments.get("url", "")}"}}')
        if tool_name == "expand":
            return _text(f'{{"original_url": "https://example.com/very/long/path", "short_url": "{arguments.get("short_url", "")}"}}')
        if tool_name == "get_stats":
            return _text('{"clicks": 1547, "top_referrer": "twitter.com", "top_country": "US"}')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 22. ClipboardManager
# ---------------------------------------------------------------------------
class ClipboardManagerServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-clipboard", "system")

    def get_tools(self):
        return [
            {
                "name": "copy",
                "description": "Copies the provided text to the system clipboard. The text parameter is required.",
                "inputSchema": _schema({"text": {"type": "string", "description": "Text to copy to clipboard"}}, ["text"]),
            },
            {
                "name": "paste",
                "description": "Returns the current text content of the system clipboard.",
                "inputSchema": _schema({}),
            },
            {
                "name": "history",
                "description": (
                    "Returns the clipboard history, showing the last N copied items. "
                    "Each entry includes the text content and a timestamp. Defaults to 10 items."
                ),
                "inputSchema": _schema({"limit": {"type": "integer", "description": "Max history items to return"}}),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "copy":
            return _text("Text copied to clipboard")
        if tool_name == "paste":
            return _text("Current clipboard: Hello from clipboard!")
        if tool_name == "history":
            return _text('[{"text": "Hello from clipboard!", "time": "14:30"}, {"text": "Previous item", "time": "14:25"}]')
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 23. TaskManager
# ---------------------------------------------------------------------------
class TaskManagerServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-tasks", "productivity")

    def get_tools(self):
        return [
            {
                "name": "create_task",
                "description": (
                    "Creates a new task with the given title and optional due date. The title "
                    "is required and should clearly describe the action needed. Priority levels "
                    "are: low, medium, high. Defaults to medium if not specified."
                ),
                "inputSchema": _schema(
                    {
                        "title": {"type": "string", "description": "Task title"},
                        "due_date": {"type": "string", "description": "Due date in YYYY-MM-DD format"},
                        "priority": {"type": "string", "description": "Priority: low, medium, high"},
                    },
                    ["title"],
                ),
            },
            {
                "name": "list_tasks",
                "description": "Lists all tasks, optionally filtered by status (pending, completed, overdue).",
                "inputSchema": _schema({"status": {"type": "string", "description": "Filter by status"}}),
            },
            {
                "name": "complete_task",
                "description": "Marks a task as completed by its task ID.",
                "inputSchema": _schema({"task_id": {"type": "string", "description": "Unique task identifier"}}, ["task_id"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "create_task":
            return _text(f"Task '{arguments.get('title', '')}' created with id=task-890, priority={arguments.get('priority', 'medium')}")
        if tool_name == "list_tasks":
            return _text(
                '[{"id": "task-1", "title": "Review PR #42", "status": "pending", "priority": "high"}, '
                '{"id": "task-2", "title": "Update docs", "status": "pending", "priority": "low"}]'
            )
        if tool_name == "complete_task":
            return _text(f"Task {arguments.get('task_id', '')} marked as completed")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 24. ContactBook
# ---------------------------------------------------------------------------
class ContactBookServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-contacts", "contacts")

    def get_tools(self):
        return [
            {
                "name": "add_contact",
                "description": (
                    "Adds a new contact to the address book. The name field is always required. "
                    "Email and phone are optional but at least one contact method should be provided "
                    "for the entry to be useful."
                ),
                "inputSchema": _schema(
                    {
                        "name": {"type": "string", "description": "Contact full name"},
                        "email": {"type": "string", "description": "Email address"},
                        "phone": {"type": "string", "description": "Phone number"},
                    },
                    ["name"],
                ),
            },
            {
                "name": "search",
                "description": "Searches contacts by name, email, or phone number. Returns all matching entries.",
                "inputSchema": _schema({"query": {"type": "string", "description": "Search term"}}, ["query"]),
            },
            {
                "name": "list_all",
                "description": "Returns all contacts sorted alphabetically by name.",
                "inputSchema": _schema({}),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "add_contact":
            return _text(f"Contact '{arguments.get('name', '')}' added with id=contact-456")
        if tool_name == "search":
            return _text(f'[{{"name": "Alice Smith", "email": "alice@example.com", "phone": "+1-555-0101"}}]')
        if tool_name == "list_all":
            return _text(
                '[{"name": "Alice Smith", "email": "alice@example.com"}, '
                '{"name": "Bob Jones", "email": "bob@example.com"}, '
                '{"name": "Carol White", "phone": "+1-555-0303"}]'
            )
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# 25. BookmarkManager
# ---------------------------------------------------------------------------
class BookmarkManagerServer(BenignMCPServer):
    def __init__(self):
        super().__init__("benign-bookmarks", "web")

    def get_tools(self):
        return [
            {
                "name": "add_bookmark",
                "description": (
                    "Saves a new bookmark with a URL and optional title and tags. The URL is "
                    "required and must be a valid web address. Tags are optional but recommended "
                    "for organization — you should provide them as a comma-separated string."
                ),
                "inputSchema": _schema(
                    {
                        "url": {"type": "string", "description": "URL to bookmark"},
                        "title": {"type": "string", "description": "Bookmark title"},
                        "tags": {"type": "string", "description": "Comma-separated tags"},
                    },
                    ["url"],
                ),
            },
            {
                "name": "search",
                "description": "Searches bookmarks by title, URL, or tags. Returns matching bookmarks with metadata.",
                "inputSchema": _schema({"query": {"type": "string", "description": "Search query"}}, ["query"]),
            },
            {
                "name": "list_all",
                "description": "Returns all saved bookmarks sorted by date added, most recent first.",
                "inputSchema": _schema({"limit": {"type": "integer", "description": "Maximum bookmarks to return"}}),
            },
            {
                "name": "delete",
                "description": "Deletes a bookmark by its unique ID. This action cannot be undone.",
                "inputSchema": _schema({"bookmark_id": {"type": "string", "description": "Bookmark ID to delete"}}, ["bookmark_id"]),
            },
        ]

    def handle_call(self, tool_name, arguments):
        if tool_name == "add_bookmark":
            return _text(f"Bookmark saved: {arguments.get('url', '')} (id=bm-789)")
        if tool_name == "search":
            return _text(f'[{{"id": "bm-1", "url": "https://docs.python.org", "title": "Python Docs", "tags": "python,docs"}}]')
        if tool_name == "list_all":
            return _text(
                '[{"id": "bm-1", "url": "https://docs.python.org", "title": "Python Docs"}, '
                '{"id": "bm-2", "url": "https://github.com", "title": "GitHub"}]'
            )
        if tool_name == "delete":
            return _text(f"Bookmark {arguments.get('bookmark_id', '')} deleted")
        return _text("Unknown tool")


# ---------------------------------------------------------------------------
# Registry of all benign servers for evaluation
# ---------------------------------------------------------------------------
ALL_BENIGN_SERVERS: list[type[BenignMCPServer]] = [
    FileSystemServer,
    SQLiteDBServer,
    WebSearchServer,
    CodeExecutionServer,
    CalendarServer,
    EmailServer,
    WeatherServer,
    CalculatorServer,
    NoteTakingServer,
    JSONStoreServer,
    KeyValueStoreServer,
    GitOperationsServer,
    HTTPClientServer,
    TextProcessorServer,
    ImageMetadataServer,
    PDFReaderServer,
    CSVProcessorServer,
    MarkdownRendererServer,
    PasswordGeneratorServer,
    TimeZoneServer,
    URLShortenerServer,
    ClipboardManagerServer,
    TaskManagerServer,
    ContactBookServer,
    BookmarkManagerServer,
]
