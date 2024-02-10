
docker_release:
    docker buildx create --append --name builder  --driver=kubernetes --platform=linux/arm64   '--driver-opt="nodeselector=kubernetes.io/arch=arm64","tolerations=key=kubernetes.io/hostname,value=server"' --node=build-arm64
    docker buildx create --append --name builder  --driver=kubernetes --platform=linux/amd64   '--driver-opt="nodeselector=kubernetes.io/arch=amd64","tolerations=key=kubernetes.io/hostname,value=toybox"' --node=build-amd64
    docker buildx use builder
    docker buildx build --platform linux/arm64,linux/amd64 -t ghcr.io/erebe/tcp_proxy:latest --push .
