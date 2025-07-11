from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """API settings.

    Attributes:
        sql_url (str): SQL URL to use for communication with the DB.
        alphabet (str): Alphabet to use for short link generation.
        secret (str): Secret used for signing tokens.
        secret_alg (str): The algorithm that 'secret' uses.
        token_expires_mins (int): Sets the minutes after which the token is
        considered expired.
    """

    sql_url: str = "sqlite:///database.db"
    alphabet: str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
    secret: str
    secret_alg: str
    token_expires_mins: int

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SHORTER_")
