import enum
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from datetime import datetime

import attr
import keyring
import keyring.errors
import structlog
import toml
import xdg.BaseDirectory

logger = structlog.get_logger()

APP_NAME = "openconnect-sso"
SESSION_KEY = f"{APP_NAME}.session"
COOKIE_KEY = "cookie"
FINGERPRINT_KEY = "fingerprint"


def datetime_converter(date):
    if date is None:
        return None
    return datetime.fromisoformat(date) if isinstance(date, str) else date


def load():
    path = xdg.BaseDirectory.load_first_config(APP_NAME)
    if not path:
        return Config()
    config_path = Path(path) / "config.toml"
    if not config_path.exists():
        return Config()
    with config_path.open() as config_file:
        try:
            return Config.from_dict(toml.load(config_file))
        except Exception:
            logger.error(
                "Could not load configuration file, ignoring",
                path=config_path,
                exc_info=True,
            )
            return Config()


def save(config):
    path = xdg.BaseDirectory.save_config_path(APP_NAME)
    config_path = Path(path) / "config.toml"
    try:
        config_path.touch()
        with config_path.open("w") as config_file:
            toml.dump(config.as_dict(), config_file)
    except Exception:
        logger.error(
            "Could not save configuration file", path=config_path, exc_info=True
        )


class AuthResponse:

    def __init__(self, session_data):
        self.server_cert_hash = session_data.fingerprint
        self.session_token = session_data.cookie


@attr.s
class ConfigNode:
    @classmethod
    def from_dict(cls, d):
        if d is None:
            return None
        return cls(**d)

    def as_dict(self):
        return attr.asdict(self)


@attr.s
class HostProfile(ConfigNode):
    address = attr.ib(converter=str)
    user_group = attr.ib(converter=str)
    name = attr.ib(converter=str)  # authgroup

    @property
    def vpn_url(self):
        parts = urlparse(self.address)
        group = self.user_group or parts.path
        if parts.path == self.address and not self.user_group:
            group = ""
        return urlunparse(
            (parts.scheme or "https", parts.netloc or self.address, group, "", "", "")
        )

    def is_same(self, other):
        return isinstance(other, HostProfile) and other.address == self.address and other.user_group == \
               self.user_group and other.name == self.name


@attr.s
class AutoFillRule(ConfigNode):
    selector = attr.ib()
    fill = attr.ib(default=None)
    action = attr.ib(default=None)


def get_default_auto_fill_rules():
    return {
        "https://*": [
            AutoFillRule(selector="div[id=passwordError]", action="stop").as_dict(),
            AutoFillRule(selector="input[type=email]", fill="username").as_dict(),
            AutoFillRule(selector="input[type=password]", fill="password").as_dict(),
            AutoFillRule(selector="input[type=submit]", action="click").as_dict(),
        ]
    }


@attr.s
class Credentials(ConfigNode):
    username = attr.ib()

    @property
    def password(self):
        try:
            return keyring.get_password(APP_NAME, self.username)
        except keyring.errors.KeyringError:
            logger.info("Cannot retrieve saved password from keyring.")
            return ""

    @password.setter
    def password(self, value):
        try:
            keyring.set_password(APP_NAME, self.username, value)
        except keyring.errors.KeyringError:
            logger.info("Cannot save password to keyring.")


@attr.s
class SessionData(ConfigNode):
    profile = attr.ib(default=None, converter=HostProfile.from_dict)
    expires = attr.ib(default=None, type=datetime, converter=datetime_converter)

    @property
    def cookie(self):
        if not self.expires or datetime.now() >= self.expires:
            return None
        try:
            return keyring.get_password(f"{SESSION_KEY}.{COOKIE_KEY}", COOKIE_KEY)
        except keyring.errors.KeyringError as e:
            logger.info("Cannot retrieve saved cookie from keyring.", error=e, msg=str(e))
        return None

    @cookie.setter
    def cookie(self, value):
        logger.info("Setting cookie", value=value)
        try:
            keyring.set_password(f"{SESSION_KEY}.{COOKIE_KEY}", COOKIE_KEY, value)
        except keyring.errors.KeyringError as e:
            logger.info("Cannot save cookie to keyring.", error=e, msg=str(e))

    @property
    def fingerprint(self):
        if not self.expires or datetime.now() >= self.expires:
            return None
        try:
            return keyring.get_password(f"{SESSION_KEY}.{FINGERPRINT_KEY}", FINGERPRINT_KEY)
        except keyring.errors.KeyringError as e:
            logger.info("Cannot retrieve saved fingerprint from keyring.", error=e, msg=str(e))
        return None

    @fingerprint.setter
    def fingerprint(self, value):
        logger.info("Setting fingerprint", value=value)
        try:
            keyring.set_password(f"{SESSION_KEY}.{FINGERPRINT_KEY}", FINGERPRINT_KEY, value)
        except keyring.errors.KeyringError as e:
            logger.info("Cannot save fingerprint to keyring.", error=e, msg=str(e))

    @property
    def is_valid(self):
        cookie = self.cookie
        fingerprint = self.fingerprint
        return cookie is not None and len(cookie) > 0 and fingerprint is not None and len(fingerprint) > 0

    def as_auth_response(self):
        return AuthResponse(self)


@attr.s
class Config(ConfigNode):
    default_profile = attr.ib(default=None, converter=HostProfile.from_dict)
    credentials = attr.ib(default=None, converter=Credentials.from_dict)
    auto_fill_rules = attr.ib(
        factory=get_default_auto_fill_rules,
        converter=lambda rules: {
            n: [AutoFillRule.from_dict(r) for r in rule] for n, rule in rules.items()
        },
    )
    session_data = attr.ib(default=None, converter=SessionData.from_dict)
    on_disconnect = attr.ib(converter=str, default="")


class DisplayMode(enum.Enum):
    HIDDEN = 0
    SHOWN = 1
