import os

from argon2.low_level import hash_secret_raw, Type

# These parameters were selected based on our Argon2id benchmark results
MEMORY_COST = 131072   # 128 MiB, kiB ,specifies how much memory each Argon2id operation uses
TIME_COST = 3 #specifies the number of processing iterations
PARALLELISM = 1#specifies the number of processing lanes used simultaneously
SALT_LENGTH = 16# A 16-byte random salt provides 128 bits of randomness, making accidental salt reuse extremely unlikely
HASH_LENGTH = 32# A 32_byte 256bit

def hash_password(password: str):
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # Convert the password from string to bytes
    password_bytes = password.encode("utf-8")

    # Generate a new random 16-byte salt
    salt = os.urandom(SALT_LENGTH)

    # Calculate the password hash using Argon2id
    password_hash = hash_secret_raw( secret=password_bytes,salt=salt,time_cost=TIME_COST,memory_cost=MEMORY_COST,parallelism=PARALLELISM,
    hash_len=HASH_LENGTH,type=Type.ID)

    # Return everything needed for later password verification
    return {"salt": salt,"password_hash": password_hash,"memory_cost": MEMORY_COST,"time_cost": TIME_COST,
    "parallelism": PARALLELISM, "hash_length": HASH_LENGTH}

def verify_password(password:str, record: dict):
    
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    # Convert the entered password to bytes
    password_bytes = password.encode("utf-8")

    # Recalculate Argon2id using the stored salt and parameters
    calculated_hash = hash_secret_raw( secret=password_bytes,salt=record["salt"],time_cost=record["time_cost"],memory_cost=record["memory_cost"],
        parallelism=record["parallelism"],hash_len=record["hash_length"],type=Type.ID)
    # Compare the calculated hash with the stored hash
    if( calculated_hash == record["password_hash"]):
        return True
    
    else:
        return False

#password = input("Enter password: ")#all time return string 

#record = hash_password(password)

#print("Salt:", record["salt"].hex())
#print("Password hash:", record["password_hash"].hex())
# Create a credential record during registration
#test case
original_password = "Mayar123"
record = hash_password(original_password)

print("Stored salt:", record["salt"].hex())
print("Stored hash:", record["password_hash"].hex())


# Test 1: Correct password
result1 = verify_password("Mayar123", record)
print("Correct password result:", result1)


# Test 2: Wrong password
result2 = verify_password("Mayar123", record)
print("Wrong password result:", result2)