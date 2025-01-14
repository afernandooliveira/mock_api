# Como executar

## 1º Passo: buildar a imagem docker
docker build -t api_sailpoint_mock/afernandojr:latest --no-cache .

## 2º Passo: executar o docker compose ou docker run

### compose
docker compose up -d

### docker run
docker run  -p 8000:8000 --rm --name sailpoint_mock api_sailpoint_mock/afernandojr:latest
