#! /bin/sh

# Example usage: ./wait-for-url.sh http://localhost echo "ready"

URL="$1"
shift

# insecure, silent, follow redirects, only print status code, all other output
# to /dev/null
CHECK="curl -ksL -w "%{http_code}" -o /dev/null $URL"

until [ $($CHECK) -eq 200 ]; do
    >&2 echo "Waiting for ${URL} to be reachable..."
    sleep 1
done

>&2 echo "Reached ${URL}. Continuing..."
exec $@
