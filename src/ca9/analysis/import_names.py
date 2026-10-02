from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

# Distributions whose import names differ from the distribution name, keyed by
# canonical distribution name. The first name is the primary import name.
CURATED_RENAMES: dict[str, tuple[str, ...]] = {
    "apache-airflow": ("airflow",),
    "apache-beam": ("apache_beam",),
    "attrs": ("attr", "attrs"),
    "azure-core": ("azure.core",),
    "azure-identity": ("azure.identity",),
    "azure-keyvault-secrets": ("azure.keyvault.secrets",),
    "azure-storage-blob": ("azure.storage.blob",),
    "beautifulsoup4": ("bs4",),
    "cx-oracle": ("cx_Oracle",),
    "discord-py": ("discord",),
    "django-allauth": ("allauth",),
    "django-celery-beat": ("django_celery_beat",),
    "django-celery-results": ("django_celery_results",),
    "django-ckeditor": ("ckeditor", "ckeditor_uploader"),
    "django-cors-headers": ("corsheaders",),
    "django-crispy-forms": ("crispy_forms",),
    "django-debug-toolbar": ("debug_toolbar",),
    "django-environ": ("environ",),
    "django-extensions": ("django_extensions",),
    "django-filter": ("django_filters",),
    "django-guardian": ("guardian",),
    "django-import-export": ("import_export",),
    "django-oauth-toolkit": ("oauth2_provider",),
    "django-redis": ("django_redis",),
    "django-rest-framework": ("rest_framework",),
    "django-storages": ("storages",),
    "djangorestframework": ("rest_framework",),
    "djangorestframework-simplejwt": ("rest_framework_simplejwt",),
    "dnspython": ("dns",),
    "drf-spectacular": ("drf_spectacular",),
    "drf-yasg": ("drf_yasg",),
    "elasticsearch-dsl": ("elasticsearch_dsl",),
    "faiss-cpu": ("faiss",),
    "faiss-gpu": ("faiss",),
    "gitpython": ("git",),
    "google-api-python-client": ("googleapiclient", "apiclient"),
    "google-auth": ("google.auth", "google.oauth2"),
    "google-auth-oauthlib": ("google_auth_oauthlib",),
    "google-cloud-bigquery": ("google.cloud.bigquery",),
    "google-cloud-pubsub": ("google.cloud.pubsub", "google.cloud.pubsub_v1"),
    "google-cloud-storage": ("google.cloud.storage",),
    "googleapis-common-protos": ("google.api", "google.rpc", "google.type", "google.longrunning"),
    "grpcio": ("grpc",),
    "grpcio-health-checking": ("grpc_health",),
    "grpcio-reflection": ("grpc_reflection",),
    "grpcio-status": ("grpc_status",),
    "grpcio-tools": ("grpc_tools",),
    "ipython": ("IPython",),
    "llama-cpp-python": ("llama_cpp",),
    "msgpack-python": ("msgpack",),
    "mysql-connector-python": ("mysql.connector", "mysqlx"),
    "mysqlclient": ("MySQLdb",),
    "opencv-contrib-python": ("cv2",),
    "opencv-contrib-python-headless": ("cv2",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "paho-mqtt": ("paho.mqtt",),
    "pillow": ("PIL",),
    "protobuf": ("google.protobuf",),
    "psycopg-binary": ("psycopg", "psycopg_binary"),
    "psycopg-c": ("psycopg", "psycopg_c"),
    "psycopg-pool": ("psycopg_pool",),
    "psycopg2-binary": ("psycopg2",),
    "py-cpuinfo": ("cpuinfo",),
    "pycairo": ("cairo",),
    "pycrypto": ("Crypto",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pygithub": ("github",),
    "pygobject": ("gi",),
    "pyhamcrest": ("hamcrest",),
    "pyinstaller": ("PyInstaller",),
    "pyjwt": ("jwt",),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "pymupdf": ("fitz", "pymupdf"),
    "pynacl": ("nacl",),
    "pyopenssl": ("OpenSSL",),
    "pypdf2": ("PyPDF2",),
    "pyqt5": ("PyQt5",),
    "pyqt6": ("PyQt6",),
    "pyserial": ("serial",),
    "pyshp": ("shapefile",),
    "pyside2": ("PySide2",),
    "pyside6": ("PySide6",),
    "pysocks": ("socks", "sockshandler"),
    "python-dateutil": ("dateutil",),
    "python-docx": ("docx",),
    "python-dotenv": ("dotenv",),
    "python-engineio": ("engineio",),
    "python-gitlab": ("gitlab",),
    "python-gnupg": ("gnupg",),
    "python-jose": ("jose",),
    "python-json-logger": ("pythonjsonlogger",),
    "python-keycloak": ("keycloak",),
    "python-ldap": ("ldap", "ldif", "ldapurl"),
    "python-magic": ("magic",),
    "python-memcached": ("memcache",),
    "python-multipart": ("multipart", "python_multipart"),
    "python-pptx": ("pptx",),
    "python-slugify": ("slugify",),
    "python-snappy": ("snappy",),
    "python-socketio": ("socketio",),
    "python-telegram-bot": ("telegram",),
    "pywin32": ("win32api", "win32con", "win32com", "win32file", "pywintypes", "pythoncom"),
    "pyxdg": ("xdg",),
    "pyyaml": ("yaml",),
    "pyzmq": ("zmq",),
    "ruamel-yaml": ("ruamel.yaml",),
    "scikit-image": ("skimage",),
    "scikit-learn": ("sklearn",),
    "sentry-sdk": ("sentry_sdk",),
    "setuptools": ("setuptools", "pkg_resources"),
    "strawberry-graphql": ("strawberry",),
    "tensorflow-cpu": ("tensorflow",),
    "tensorflow-gpu": ("tensorflow",),
    "typing-extensions": ("typing_extensions",),
    "websocket-client": ("websocket",),
    "zope-interface": ("zope.interface",),
}

# Popular distributions whose import name is the distribution name with "-"
# replaced by "_". Listing them makes that mapping authoritative without metadata.
_CURATED_IDENTITY: frozenset[str] = frozenset(
    {
        "aiofiles",
        "aiohttp",
        "aiosqlite",
        "alembic",
        "anyio",
        "asyncpg",
        "authlib",
        "babel",
        "bcrypt",
        "bleach",
        "boto3",
        "botocore",
        "bottle",
        "celery",
        "certifi",
        "cffi",
        "channels",
        "chardet",
        "charset-normalizer",
        "click",
        "cryptography",
        "daphne",
        "dill",
        "django",
        "docutils",
        "ecdsa",
        "fastapi",
        "filelock",
        "flask",
        "flask-cors",
        "flask-login",
        "flask-sqlalchemy",
        "flask-wtf",
        "gevent",
        "gunicorn",
        "h11",
        "h2",
        "httpcore",
        "httplib2",
        "httpx",
        "hypercorn",
        "idna",
        "itsdangerous",
        "jinja2",
        "joblib",
        "jsonpickle",
        "jsonschema",
        "keras",
        "kombu",
        "ldap3",
        "lxml",
        "mako",
        "markdown",
        "markupsafe",
        "marshmallow",
        "matplotlib",
        "mlflow",
        "nltk",
        "numpy",
        "oauthlib",
        "onnx",
        "openpyxl",
        "oracledb",
        "orjson",
        "pandas",
        "paramiko",
        "passlib",
        "pip",
        "psutil",
        "psycopg",
        "psycopg2",
        "pyarrow",
        "pyasn1",
        "pyasn1-modules",
        "pycparser",
        "pydantic",
        "pygments",
        "pymysql",
        "pyodbc",
        "pyparsing",
        "pytest",
        "pytz",
        "redis",
        "requests",
        "rsa",
        "sanic",
        "scipy",
        "scrapy",
        "selenium",
        "simplejson",
        "six",
        "sqlalchemy",
        "sqlparse",
        "starlette",
        "toml",
        "tomli",
        "torch",
        "tornado",
        "tqdm",
        "transformers",
        "twisted",
        "ujson",
        "urllib3",
        "uvicorn",
        "waitress",
        "websockets",
        "werkzeug",
        "wheel",
        "wtforms",
        "xlrd",
        "xlsxwriter",
        "zipp",
    }
)

# Distributions commonly loaded without an import statement in project code:
# servers and CLIs, database drivers selected by URL, and plugins or engines
# chosen by a string. "Not imported" cannot show these are unused. Each value
# completes the sentence "'<package>' ...".
INDIRECT_USE_PACKAGES: dict[str, str] = {
    "aiodns": "is used automatically by aiohttp when installed",
    "aiomysql": "is a database driver selected by connection URL",
    "aiosqlite": "is a database driver selected by connection URL",
    "alembic": "is a migration tool usually run from the command line",
    "asyncpg": "is a database driver selected by connection URL",
    "brotli": "is a compression codec used automatically by HTTP clients when installed",
    "brotlicffi": "is a compression codec used automatically by HTTP clients when installed",
    "celery": "is a task worker usually started from the command line",
    "cx-oracle": "is a database driver selected by connection URL",
    "daphne": "is an ASGI server usually started from the command line",
    "eventlet": "is a worker class selected by server configuration",
    "fastparquet": "is a parquet engine selected by pandas at runtime",
    "flower": "is a monitoring server usually started from the command line",
    "gevent": "is a worker class selected by server configuration",
    "granian": "is an ASGI/WSGI server usually started from the command line",
    "gunicorn": "is a WSGI server usually started from the command line",
    "hiredis": "is a parser used automatically by redis-py when installed",
    "html5lib": "is a parser selected by name in BeautifulSoup or pandas",
    "httptools": "is a HTTP parser used automatically by uvicorn when installed",
    "hypercorn": "is an ASGI server usually started from the command line",
    "lxml": "is a parser selected by name in BeautifulSoup, pandas, or other libraries",
    "mysql-connector-python": "is a database driver selected by connection URL",
    "mysqlclient": "is a database driver selected by connection URL (Django/SQLAlchemy default)",
    "odfpy": "is a spreadsheet engine selected by pandas at runtime",
    "openpyxl": "is a spreadsheet engine selected by pandas at runtime",
    "oracledb": "is a database driver selected by connection URL",
    "pg8000": "is a database driver selected by connection URL",
    "pillow": "is an image library loaded by frameworks such as Django ImageField",
    "pip": "is an installer usually run from the command line",
    "psycopg": "is a database driver selected by connection URL",
    "psycopg-binary": "is a database driver selected by connection URL",
    "psycopg-c": "is a database driver selected by connection URL",
    "psycopg2": "is a database driver selected by connection URL (Django/SQLAlchemy default)",
    "psycopg2-binary": "is a database driver selected by connection URL (Django/SQLAlchemy default)",
    "pyarrow": "is an engine selected by pandas at runtime",
    "pylibmc": "is a cache backend selected by configuration",
    "pymemcache": "is a cache backend selected by configuration",
    "pymssql": "is a database driver selected by connection URL",
    "pymysql": "is a database driver selected by connection URL",
    "pyodbc": "is a database driver selected by connection URL",
    "python-calamine": "is a spreadsheet engine selected by pandas at runtime",
    "python-memcached": "is a cache backend selected by configuration",
    "pyxlsb": "is a spreadsheet engine selected by pandas at runtime",
    "redis": "is a cache, broker, or session backend selected by configuration",
    "setuptools": "is build tooling; pkg_resources is loaded by many libraries",
    "simplejson": "is used automatically by libraries such as requests when installed",
    "supervisor": "is a process manager usually started from the command line",
    "tables": "is an HDF5 engine selected by pandas at runtime",
    "uvicorn": "is an ASGI server usually started from the command line",
    "uvloop": "is an event loop used automatically by servers when installed",
    "waitress": "is a WSGI server usually started from the command line",
    "watchfiles": "is a file watcher used automatically by uvicorn reload",
    "wheel": "is build tooling usually run from the command line",
    "xlrd": "is a spreadsheet engine selected by pandas at runtime",
    "xlsxwriter": "is a spreadsheet engine selected by pandas at runtime",
    "xlwt": "is a spreadsheet engine selected by pandas at runtime",
    "zstandard": "is a compression codec used automatically by HTTP clients when installed",
}

_IGNORED_MODULE_NAMES = frozenset(
    {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks"}
)


def _guess_import_name(package_name: str) -> str:
    return package_name.lower().replace("-", "_")


def curated_import_names(package_name: str) -> tuple[str, ...]:
    key = canonicalize_name(package_name)
    if key in CURATED_RENAMES:
        return CURATED_RENAMES[key]
    if key in _CURATED_IDENTITY:
        return (key.replace("-", "_"),)
    return ()


@dataclass(frozen=True)
class ImportNameResolution:
    package: str
    names: tuple[str, ...]
    source: str  # metadata, curated, or guessed
    installed: bool = False

    @property
    def primary(self) -> str:
        return self.names[0]

    @property
    def authoritative(self) -> bool:
        return self.source in ("metadata", "curated")


def _module_name_from_file(filename: str) -> str | None:
    if filename.endswith(".py"):
        stem = filename[:-3]
    elif filename.endswith((".so", ".pyd")):
        stem = filename.split(".", 1)[0]
    else:
        return None
    if stem.isidentifier():
        return stem
    return None


def _record_module_names(dist: importlib.metadata.Distribution) -> set[str] | None:
    try:
        files = dist.files
    except Exception:
        return None
    if not files:
        return None

    parts_set = {tuple(f.parts) for f in files}
    names: set[str] = set()
    for parts in parts_set:
        if not parts or parts[0] in ("..", "__pycache__"):
            continue
        if parts[0].endswith((".dist-info", ".egg-info", ".data")):
            continue
        if len(parts) == 1:
            module = _module_name_from_file(parts[0])
            if module:
                names.add(module)
            continue
        top = parts[0]
        if not top.isidentifier():
            continue
        if (top, "__init__.py") in parts_set:
            names.add(top)
            continue
        # PEP 420 namespace: the distribution is identified by its subpackage.
        # Data directories without Python files are not importable names.
        if len(parts) == 2:
            sub = _module_name_from_file(parts[1])
        elif parts[-1].endswith(".py") and parts[1].isidentifier() and parts[1] != "__pycache__":
            sub = parts[1]
        else:
            sub = None
        if sub:
            names.add(f"{top}.{sub}")
    return names


def _distribution_module_names(dist: importlib.metadata.Distribution) -> tuple[str, ...]:
    record_names = _record_module_names(dist)
    try:
        top_level = dist.read_text("top_level.txt")
    except Exception:
        top_level = None

    names: set[str] = set()
    if top_level:
        for line in top_level.splitlines():
            name = line.strip().replace("/", ".")
            if not name or not all(part.isidentifier() for part in name.split(".")):
                continue
            refined = {n for n in record_names or () if n.startswith(name + ".")}
            if refined and name not in (record_names or ()):
                names.update(refined)
            else:
                names.add(name)
    elif record_names:
        names = record_names

    names = {n for n in names if n.split(".", 1)[0] not in _IGNORED_MODULE_NAMES}
    public = {n for n in names if not n.split(".", 1)[0].startswith("_")}
    return tuple(sorted(public or names))


@dataclass
class EnvironmentIndex:
    """Installed distribution metadata for the environment ca9 analyzes."""

    distributions: dict[str, importlib.metadata.Distribution] = field(default_factory=dict)
    available: bool = True
    _module_names: dict[str, tuple[str, ...]] = field(default_factory=dict)
    _resolutions: dict[str, ImportNameResolution] = field(default_factory=dict)

    @classmethod
    def from_environment(cls) -> EnvironmentIndex:
        index = cls()
        try:
            dists = list(importlib.metadata.distributions())
        except Exception:
            index.available = False
            return index
        for dist in dists:
            try:
                name = dist.metadata["Name"]
            except Exception:
                continue
            if not name:
                continue
            # First match on sys.path wins, matching what an import would load.
            index.distributions.setdefault(canonicalize_name(name), dist)
        return index

    def is_installed(self, package_name: str) -> bool:
        return canonicalize_name(package_name) in self.distributions

    def module_names(self, package_name: str) -> tuple[str, ...]:
        key = canonicalize_name(package_name)
        if key not in self._module_names:
            dist = self.distributions.get(key)
            self._module_names[key] = _distribution_module_names(dist) if dist else ()
        return self._module_names[key]

    def version(self, package_name: str) -> str | None:
        dist = self.distributions.get(canonicalize_name(package_name))
        if dist is None:
            return None
        try:
            return dist.version
        except Exception:
            return None

    def entry_points(self, package_name: str) -> dict[str, tuple[str, ...]]:
        dist = self.distributions.get(canonicalize_name(package_name))
        if dist is None:
            return {}
        groups: dict[str, list[str]] = {}
        try:
            for ep in dist.entry_points:
                groups.setdefault(ep.group, []).append(ep.name)
        except Exception:
            return {}
        return {group: tuple(sorted(names)) for group, names in sorted(groups.items())}

    def requirements(self, package_name: str) -> list[str]:
        dist = self.distributions.get(canonicalize_name(package_name))
        if dist is None:
            return []
        try:
            return list(dist.requires or [])
        except Exception:
            return []

    def resolve(self, package_name: str) -> ImportNameResolution:
        key = canonicalize_name(package_name)
        cached = self._resolutions.get(key)
        if cached is not None:
            return cached

        guess = _guess_import_name(package_name)
        curated = curated_import_names(package_name)
        metadata = self.module_names(package_name)
        installed = self.is_installed(package_name)

        if metadata:
            # Curated names refine namespace packages (protobuf -> google.protobuf),
            # so drop metadata names that are only a parent of a curated name.
            extra = [
                name
                for name in metadata
                if name not in curated and not any(c.startswith(name + ".") for c in curated)
            ]
            if not curated:
                extra.sort(key=lambda name: (name.lower() != guess.lower(), name))
            resolution = ImportNameResolution(
                key, tuple(curated) + tuple(extra), "metadata", installed
            )
        elif curated:
            resolution = ImportNameResolution(key, curated, "curated", installed)
        else:
            resolution = ImportNameResolution(key, (guess,), "guessed", installed)

        self._resolutions[key] = resolution
        return resolution


_INDEX: EnvironmentIndex | None = None


def environment_index() -> EnvironmentIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = EnvironmentIndex.from_environment()
    return _INDEX


def reset_environment_index() -> None:
    """Forget cached metadata so the next lookup sees the current environment."""
    global _INDEX
    _INDEX = None


def resolve_import_names(package_name: str) -> ImportNameResolution:
    return environment_index().resolve(package_name)
