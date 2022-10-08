echo "Building engine....."
docker build -t engine .

echo "Starting Engine......"
docker run -p 8080:3030 --rm --name engine1 engine