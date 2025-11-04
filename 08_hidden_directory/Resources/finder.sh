START_DIR="${1:-.}"

find "$START_DIR" -type f -iname "README*" | while read -r file; do
    cat "$file"
done