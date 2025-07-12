from passlib.context import CryptContext

pass_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_passwd(plain: str, hashed: str) -> bool:
    """Compare a plain password against a provided hashed version.

    Args:
        plain (str): The plain passowrd to compare.
        hashed (str): The hashed version of the password to compare against.

    Returns:
        bool: 'True' if 'hashed' is the hashed version of the 'plain', False otherwise."""

    return pass_ctx.verify(plain, hashed)


def hash_passwd(plain: str) -> str:
    """Hash the provided password.

    Args:
        plain (str): The plain password to be hashed.

    Returns:
        str: The hashed password.
    """

    return pass_ctx.hash(plain)
