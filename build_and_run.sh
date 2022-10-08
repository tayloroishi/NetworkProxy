echo "Building Proxy....."
docker build -t engine .

echo "Starting Proxy......"
docker run -p 8080:3030 --rm --name engine1 engine