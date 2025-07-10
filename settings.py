from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """API settings.

    Attributes:
        shorter_sql_url (str): SQL URL to use for communication with the DB.
        shorter_alphabet (str): Alphabet to use for short link generation.
    """

    shorter_sql_url: str = "sqlite:///database.db"
    shorter_alphabet: str = (
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
    )
    shorter_secret: str
    shorter_secret_alg: str
    shorter_token_expires_mins: int

    model_config = SettingsConfigDict(env_file=".env")
