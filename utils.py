



def print_dictionary(data: dict, indent: int = 0) -> None:
    for key, value in data.items():
        if isinstance(value, dict):
            print(" " * indent + f"{key}:")
            print_dictionary(value, indent + 4)
        else:
            print(" " * indent + f"{key}: {value}")