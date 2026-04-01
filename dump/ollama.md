docker run -d -p 11434:11434 ollama/ollama
docker ps 
---> take the name
docker exec -it <container-name> ollama pull phi

<!-- for models -->
curl http://localhost:11434/api/tags

<!-- basic response style -->
curl http://localhost:11434/api/generate -d '{
  "model": "phi:latest",
  "prompt": "Answer as fast as you can, Who are you and where are you running",
  "stream": false
}' | jq -r .

<!-- streaming response aka chat style aka word by word in streams-->
curl http://localhost:11434/api/generate -d '{
  "model": "phi:latest",
  "prompt": "Write a short poem on DevOps"
}'

curl http://localhost:11434/api/chat -d '{
  "model": "phi:latest",
  "messages": [
    {"role": "user", "content": "What is AWS EKS?"}
  ]
}'