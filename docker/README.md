# Geneva Docker

This implements the Docker base image for Geneva. You can run the base image with the below python:
```
import os
import docker

docker_client = docker.from_env()
docker_client.containers.run('base', detach=True, privileged=True, volumes={os.path.abspath(os.getcwd()): {"bind" : "/code", "mode" : "rw"}}, tty=True, remove=True, name="test")
```
