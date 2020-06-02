# Geneva Docker

This implements the Docker base image for Geneva. Each docker container used by the evaluator runs out of the same base container.

To build it:
```
docker build -t base:latest -f docker/Dockerfile .
```

Optionally, to manually run/inspect the docker image to explore the image, run:

```
docker run -it base
```

You can run the base image with the below python:
```python
import os
import docker

docker_client = docker.from_env()
docker_client.containers.run('base', detach=True, privileged=True, volumes={os.path.abspath(os.getcwd()): {"bind" : "/code", "mode" : "rw"}}, tty=True, remove=True, name="test")
```
