from getpass import getpass
import requests
import hashlib
import sys


def requestAPIData(query_char):
    # query_char is the first 5 char from converted sha1
    url = f"https://api.pwnedpasswords.com/range/{query_char}"

    # response returns either success-status(<Response [200]>) or bad-request(<Response [400]>)
    response = requests.get(url)
    if response.status_code != 200:
        print(
            f"Error fetching : {response.status_code}, check the api and try again!")
    return response


def getPasswordLeakCount(hashes, hash_to_check):
    # Converting response to text and split w.r.t each line
    hashes = [line.split(':') for line in hashes.text.splitlines()]
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwnedAPICheck(password):
    # Converting password to sha1 hashes
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Extracting first 5 and the rest char from converted hash
    first5_char, tail = sha1Password[:5], sha1Password[5:]

    # Checking if first 5 char is a valid hash in DB via API
    # Returns gen-obj of sha1[5:] => <Response [200]> if valid else => <Response [400]>
    response = requestAPIData(first5_char)

    # getPasswordLeakCount returns count of how many times people have used similar password
    return getPasswordLeakCount(response, tail)
    ...


def main(enteredPasswords):
    for password in enteredPasswords:
        count = pwnedAPICheck(password)
        if count:
            print(
                f"{password} was found {count} times... you should probably change your password")
        else:
            print(f"{password} was NOT found. Carry on!")

    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1:])

    else:
        password = getpass(prompt="Enter your password : ").split()
        main(password)
