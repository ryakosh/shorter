def build_encoder(alphabet: str):
    """Build an encoder using the provided 'alphabet'.

    Args:
        alphabet (str): The alphabet string consisting of characters to use.

    Returns:
        callable: A function that takes a number and encodes it.
    """
    alphabet_tup = tuple(alphabet)  # Speed optimization
    alphabet_len = len(alphabet)

    def encoder(num: int) -> str:
        """Encode a number to it's string representation.

        Args:
            num (int): Number to be encoded.

        Returns:
            str: String representation of the 'num'.
        """

        if num == 0:
            return alphabet_tup[0]

        res = ""
        while num:
            num, rem = divmod(num, alphabet_len)
            res += alphabet_tup[rem]

        return res

    return encoder
