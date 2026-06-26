"""Intentionally vulnerable sample for scanner testing."""
import os
import pickle
import subprocess


# Hardcoded secret
API_KEY = "ak_live_1234567890abcdef1234567890abcdef"


def run_user_command(user_input):
    # Command injection
    os.system("ls " + user_input)


def query_db(user_input):
    # SQL injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)


def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)


def shell_exec(cmd):
    # shell=True with subprocess
    subprocess.run(cmd, shell=True)


def dynamic_code(user_input):
    # Arbitrary code execution
    exec(user_input)
